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

This module is intentionally decoupled from the LLM provider: swapping the
Hugging Face endpoint model id is a one-line change, and a mock mode lets
the rest of the system (API, UI, tests) run with zero HF API calls/cost.
"""

import json
import os
from dataclasses import dataclass

from langchain_core.prompts import ChatPromptTemplate
from langchain_huggingface import HuggingFaceEndpoint, ChatHuggingFace

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


@dataclass
class TriageResult:
    incident: Incident
    mitre_tactic: str
    llm_severity: str
    is_likely_false_positive: bool
    analyst_summary: str
    recommended_action: str


def _get_chat_model(model_id: str = "HuggingFaceH4/zephyr-7b-beta") -> ChatHuggingFace:
    """Builds a LangChain ChatHuggingFace wrapper around a Hugging Face
    Inference Endpoint. Requires HUGGINGFACEHUB_API_TOKEN to be set."""
    llm = HuggingFaceEndpoint(
        repo_id=model_id,
        max_new_tokens=512,
        temperature=0.2,          # low temperature: we want consistent JSON, not creativity
        repetition_penalty=1.05,
    )
    return ChatHuggingFace(llm=llm)


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


def triage_incident(incident: Incident, use_llm: bool = False,
                     model_id: str = "HuggingFaceH4/zephyr-7b-beta") -> TriageResult:
    """Main entry point. Set use_llm=True (and export HUGGINGFACEHUB_API_TOKEN)
    to route through the real Hugging Face model; otherwise falls back to a
    deterministic mock so the project demos without API costs/keys."""
    if not use_llm or not os.environ.get("HUGGINGFACEHUB_API_TOKEN"):
        return _mock_triage(incident)

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

    try:
        parsed = json.loads(response.content.strip().strip("`").lstrip("json"))
        return TriageResult(
            incident=incident,
            mitre_tactic=parsed.get("mitre_tactic", "Discovery"),
            llm_severity=parsed.get("severity", incident.severity.value),
            is_likely_false_positive=bool(parsed.get("is_likely_false_positive", False)),
            analyst_summary=parsed.get("analyst_summary", ""),
            recommended_action=parsed.get("recommended_action", ""),
        )
    except (json.JSONDecodeError, AttributeError):
        # If the model returns malformed JSON, degrade gracefully instead of
        # crashing the whole pipeline -- fall back to the mock for this incident.
        return _mock_triage(incident)


def triage_all(incidents: list[Incident], use_llm: bool = False) -> list[TriageResult]:
    return [triage_incident(i, use_llm=use_llm) for i in incidents]
