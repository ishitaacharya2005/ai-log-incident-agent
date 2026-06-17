"""
report_agent.py
-----------------
Takes a list of TriageResults (already classified and severity-scored) and
produces a structured incident report: an executive summary section for
non-technical stakeholders, and a technical detail section for the SOC
team. This is a separate agent from triage_agent deliberately -- triage is
"classify and score", report generation is "communicate to humans", and
keeping them separate means each prompt stays focused and each step can be
tested/swapped independently (e.g. swapping in a different summarization
model without touching classification logic).
"""

import os
from dataclasses import dataclass
from datetime import datetime

from langchain_core.prompts import ChatPromptTemplate

from app.agents.triage_agent import TriageResult, _get_chat_model

_REPORT_SYSTEM_PROMPT = """You are a security report writer. Given a list \
of triaged security incidents, write a concise executive summary (3-5 \
sentences, no jargon, suitable for a non-technical manager) describing \
the overall security posture implied by these incidents. Do not list every \
incident individually; synthesize patterns and overall risk level."""


@dataclass
class IncidentReport:
    generated_at: str
    total_incidents: int
    severity_breakdown: dict
    executive_summary: str
    triage_results: list[TriageResult]


def _severity_breakdown(results: list[TriageResult]) -> dict:
    breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for r in results:
        breakdown[r.llm_severity] = breakdown.get(r.llm_severity, 0) + 1
    return breakdown


def _mock_executive_summary(results: list[TriageResult], breakdown: dict) -> str:
    if not results:
        return "No security incidents were detected in the analyzed log window."

    top_tactic = max(
        {r.mitre_tactic for r in results},
        key=lambda t: sum(1 for r in results if r.mitre_tactic == t),
    )
    high_risk = breakdown.get("high", 0) + breakdown.get("critical", 0)
    return (
        f"During this analysis window, {len(results)} security incidents were detected, "
        f"with {high_risk} classified as high or critical severity. The most common "
        f"attacker tactic observed was '{top_tactic}'. Immediate review is recommended "
        "for all critical-severity findings, with particular attention to source IPs "
        "exhibiting repeated or multi-vector behavior."
    )


def generate_report(results: list[TriageResult], use_llm: bool = False,
                     model_id: str = "HuggingFaceH4/zephyr-7b-beta") -> IncidentReport:
    breakdown = _severity_breakdown(results)

    if not use_llm or not os.environ.get("HUGGINGFACEHUB_API_TOKEN"):
        summary = _mock_executive_summary(results, breakdown)
    else:
        chat = _get_chat_model(model_id)
        prompt = ChatPromptTemplate.from_messages([
            ("system", _REPORT_SYSTEM_PROMPT),
            ("user", "Incidents:\n{incidents}\nSeverity breakdown: {breakdown}"),
        ])
        incidents_text = "\n".join(
            f"- {r.incident.incident_type.value} from {r.incident.src_ip} "
            f"(tactic: {r.mitre_tactic}, severity: {r.llm_severity})"
            for r in results
        )
        chain = prompt | chat
        response = chain.invoke({"incidents": incidents_text, "breakdown": breakdown})
        summary = response.content.strip()

    return IncidentReport(
        generated_at=datetime.utcnow().isoformat() + "Z",
        total_incidents=len(results),
        severity_breakdown=breakdown,
        executive_summary=summary,
        triage_results=results,
    )


def report_to_dict(report: IncidentReport) -> dict:
    """Serializable form for the API / frontend."""
    return {
        "generated_at": report.generated_at,
        "total_incidents": report.total_incidents,
        "severity_breakdown": report.severity_breakdown,
        "executive_summary": report.executive_summary,
        "incidents": [
            {
                "incident_type": r.incident.incident_type.value,
                "src_ip": r.incident.src_ip,
                "detector": r.incident.detector,
                "detector_confidence": round(r.incident.confidence, 2),
                "mitre_tactic": r.mitre_tactic,
                "severity": r.llm_severity,
                "is_likely_false_positive": r.is_likely_false_positive,
                "analyst_summary": r.analyst_summary,
                "recommended_action": r.recommended_action,
                "evidence_count": len(r.incident.evidence_events),
                "sample_evidence": [e.raw_line for e in r.incident.evidence_events[:3]],
            }
            for r in report.triage_results
        ],
    }
