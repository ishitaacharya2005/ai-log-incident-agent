"""
triage_agent.py
-----------------
LangChain + Hugging Face powered layer that takes the structured Incidents
produced by the rule-based and ML detectors and:

  1. Classifies each incident against a simplified MITRE ATT&CK-style
     tactic taxonomy (gives the LLM's output a recognized security
     framework to anchor to, instead of inventing ad-hoc categories).
  2. Assigns/refines a severity judgement that considers context the
     numeric detectors can't see (e.g. "5 failed logins against a
     honeypot account" vs "5 failed logins against a production admin
     account" should not be treated the same way).
  3. Writes a short analyst-style justification per incident.

NOTE on the LLM client: Hugging Face deprecated the old serverless
endpoint at api-inference.huggingface.co in favor of a unified,
OpenAI-compatible "Inference Providers" router at
https://router.huggingface.co/v1, which proxies to 15+ backend providers
(Together AI, Fireworks, Groq, etc.) for any given model.

We still use LangChain for prompt templating and chain composition
(ChatPromptTemplate, LCEL `prompt | chat`), but the chat model itself is
langchain_openai's ChatOpenAI pointed at the HF router via base_url --
this is the officially documented pattern for OpenAI-API-compatible
third-party endpoints (see Hugging Face's own TGI Messages API docs,
which show this exact ChatOpenAI + custom base_url integration). The
langchain_huggingface package's HuggingFaceEndpoint/ChatHuggingFace
classes still target the deprecated hostname as of this writing.
"""

import json
import os
from dataclasses import dataclass

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from app.core.anomaly_detector import Incident

MITRE_TACTICS = [
    "Initial Access", "Credential Access", "Discovery",
    "Reconnaissance", "Lateral Movement", "Persistence", "Impact",
]

_TRIAGE_SYSTEM_PROMPT = """You are a SOC (Security Operations Center) tier-2 \
analyst assistant. You are given structured evidence about a detected \
security incident. Respond ONLY with a JSON object, no preamble, no \
markdown fences, with exactly these keys:

- "mitre_tactic": one of {tactics}
- "severity": one of ["low", "medium", "high", "critical"]
- "is_likely_false_positive": boolean
- "analyst_summary": a 2-3 sentence plain-English explanation an engineer \
who is not a security specialist could understand, including what \
happened and why it matters.
- "recommended_action": one concise, concrete next step.
"""

_TRIAGE_USER_TEMPLATE = """Incident type: {incident_type}
Source IP: {src_ip}
Detector: {detector}
Detector confidence: {confidence}
Detector notes: {notes}
Sample evidence (raw log lines, up to 5):
{evidence_sample}
"""

# Routed through Hugging Face's unified Inference Providers gateway.
# ":fastest" lets HF auto-pick whichever backend provider is currently
# serving this model fastest. Swap this to any chat model on the Hub
# that has an active inference provider.
DEFAULT_MODEL = "deepseek-ai/DeepSeek-V3:fastest"

HF_ROUTER_BASE_URL = "https://router.huggingface.co/v1"


@dataclass
class TriageResult:
    incident: Incident
    mitre_tactic: str
    llm_severity: str
    is_likely_false_positive: bool
    analyst_summary: str
    recommended_action: str


def _get_chat_model(model_id: str = DEFAULT_MODEL) -> ChatOpenAI:
    """Builds a LangChain ChatOpenAI instance pointed at Hugging Face's
    OpenAI-compatible router endpoint. Requires HUGGINGFACEHUB_API_TOKEN
    (or HF_TOKEN) to be set in the environment.

    This replaces the older langchain_huggingface.ChatHuggingFace, which
    still points at the deprecated api-inference.huggingface.co host.
    ChatOpenAI's base_url override is the documented way to talk to any
    OpenAI-API-compatible third-party endpoint from inside LangChain.
    """
    token = os.environ.get("HUGGINGFACEHUB_API_TOKEN") or os.environ.get("HF_TOKEN")
    return ChatOpenAI(
        model=model_id,
        api_key=token,
        base_url=HF_ROUTER_BASE_URL,
        max_tokens=512,
        temperature=0.2,   # low temperature: consistent JSON, not creativity
    )


def _build_prompt() -> ChatPromptTemplate:
    return ChatPromptTemplate.from_messages([
        ("system", _TRIAGE_SYSTEM_PROMPT.format(tactics=MITRE_TACTICS)),
        ("user", _TRIAGE_USER_TEMPLATE),
    ])


def _mock_triage(incident: Incident) -> TriageResult:
    """Deterministic, zero-cost stand-in for the LLM call. Used by default
    in tests/demos so the pipeline is fully runnable without a Hugging Face
    API token. Mirrors the structure the real model is prompted to return."""
    tactic_map = {
        "brute_force_login_attempt": "Credential Access",
        "port_scan": "Reconnaissance",
        "directory_enumeration": "Discovery",
        "statistical_behavioral_anomaly": "Discovery",
    }
    tactic = tactic_map.get(incident.incident_type.value, "Discovery")
    return TriageResult(
        incident=incident,
        mitre_tactic=tactic,
        llm_severity=incident.severity.value,
        is_likely_false_positive=incident.confidence < 0.4,
        analyst_summary=(
            f"Source IP {incident.src_ip} triggered a {incident.incident_type.value} "
            f"detection via the {incident.detector} engine. {incident.notes}"
        ),
        recommended_action=(
            f"Temporarily rate-limit or block {incident.src_ip} at the firewall and "
            "review the affected account/service for compromise."
        ),
    )


def _clean_json_block(text: str) -> str:
    """Strip markdown code fences (```json ... ``` or ``` ... ```) some
    models wrap their JSON output in. Deliberately explicit instead of
    .lstrip("json"), which strips matching *characters* from the left
    edge repeatedly rather than the literal substring "json" -- a subtle
    bug that could silently corrupt valid JSON starting with those letters."""
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


def triage_incident(incident: Incident, use_llm: bool = False,
                     model_id: str = DEFAULT_MODEL) -> TriageResult:
    """Main entry point. Set use_llm=True (and export HUGGINGFACEHUB_API_TOKEN)
    to route through the real Hugging Face model; otherwise falls back to a
    deterministic mock so the project demos without API costs/keys."""
    if not use_llm or not (os.environ.get("HUGGINGFACEHUB_API_TOKEN") or os.environ.get("HF_TOKEN")):
        return _mock_triage(incident)

    # Entire LLM call + parse wrapped in one try/except so ANY failure mode
    # (network/DNS issues, auth errors, the model being unavailable,
    # malformed JSON in the response) degrades gracefully to the mock
    # instead of crashing the whole pipeline -- this is the graceful
    # degradation behavior the README describes.
    try:
        chat = _get_chat_model(model_id)
        prompt = _build_prompt()
        evidence_sample = "\n".join(e.raw_line for e in incident.evidence_events[:5])

        chain = prompt | chat
        response = chain.invoke({
            "incident_type": incident.incident_type.value,
            "src_ip": incident.src_ip,
            "detector": incident.detector,
            "confidence": incident.confidence,
            "notes": incident.notes,
            "evidence_sample": evidence_sample,
        })

        parsed = json.loads(_clean_json_block(response.content))
        return TriageResult(
            incident=incident,
            mitre_tactic=parsed.get("mitre_tactic", "Discovery"),
            llm_severity=parsed.get("severity", incident.severity.value),
            is_likely_false_positive=bool(parsed.get("is_likely_false_positive", False)),
            analyst_summary=parsed.get("analyst_summary", ""),
            recommended_action=parsed.get("recommended_action", ""),
        )
    except Exception as exc:
        print(f"[LLM FALLBACK - triage] {type(exc).__name__}: {exc}")
        return _mock_triage(incident)


def triage_all(incidents: list[Incident], use_llm: bool = False) -> list[TriageResult]:
    return [triage_incident(i, use_llm=use_llm) for i in incidents]