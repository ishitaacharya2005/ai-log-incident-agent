"""
anomaly_detector.py
--------------------
Detects suspicious behavior in parsed log events using two complementary
techniques, deliberately combined rather than relying on one:

1. Rule-based heuristics for well-understood attack signatures
   (brute force, port scanning, directory enumeration). These are fast,
   explainable, and catch the "obvious" cases with zero false-negative risk
   on patterns we already know.

2. An unsupervised ML model (Isolation Forest) over engineered behavioral
   features per source IP, to catch anomalies that don't match a known
   signature -- e.g. a single IP behaving statistically unlike the rest of
   the traffic. This is the part that makes the system more than a
   keyword-matcher and is worth highlighting in an interview: it's
   detecting *novel* anomalous behavior, not just known patterns.

Both layers feed into the same Incident object so the LLM agent downstream
gets a consistent structure regardless of which layer flagged it.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.log_parser import LogEvent, LogSource


class IncidentType(str, Enum):
    BRUTE_FORCE = "brute_force_login_attempt"
    PORT_SCAN = "port_scan"
    DIR_ENUMERATION = "directory_enumeration"
    STATISTICAL_ANOMALY = "statistical_behavioral_anomaly"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Incident:
    incident_type: IncidentType
    src_ip: str
    severity: Severity
    evidence_events: list[LogEvent]
    detector: str               # "rule_based" or "isolation_forest"
    confidence: float = 1.0
    notes: str = ""
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule-based detectors
# ---------------------------------------------------------------------------

def detect_brute_force(events: list[LogEvent], threshold: int = 5,
                        window_minutes: int = 10) -> list[Incident]:
    """Flag an IP as brute-forcing if it racks up >= threshold failed SSH
    logins within a rolling time window."""
    failed = [e for e in events
              if e.source == LogSource.SSH_AUTH
              and e.action in ("failed_password", "invalid_user")
              and e.timestamp and e.src_ip]

    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in failed:
        by_ip[e.src_ip].append(e)

    incidents = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        window = []
        for e in ip_events:
            window.append(e)
            window = [w for w in window if e.timestamp - w.timestamp <= timedelta(minutes=window_minutes)]
            if len(window) >= threshold:
                severity = Severity.CRITICAL if len(window) >= threshold * 2 else Severity.HIGH
                incidents.append(Incident(
                    incident_type=IncidentType.BRUTE_FORCE,
                    src_ip=ip,
                    severity=severity,
                    evidence_events=list(window),
                    detector="rule_based",
                    notes=f"{len(window)} failed login attempts within {window_minutes} minutes",
                ))
                window = []  # reset after flagging to avoid duplicate overlapping incidents
    return incidents


def detect_port_scan(events: list[LogEvent], distinct_ports_threshold: int = 8,
                      window_minutes: int = 5) -> list[Incident]:
    """Flag an IP probing many distinct destination ports in a short window,
    a classic port scanning signature."""
    fw_events = [e for e in events
                 if e.source == LogSource.FIREWALL and e.src_ip and e.timestamp]

    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in fw_events:
        by_ip[e.src_ip].append(e)

    incidents = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        window = []
        for e in ip_events:
            window.append(e)
            window = [w for w in window if e.timestamp - w.timestamp <= timedelta(minutes=window_minutes)]
            distinct_ports = {w.target for w in window if w.target}
            if len(distinct_ports) >= distinct_ports_threshold:
                incidents.append(Incident(
                    incident_type=IncidentType.PORT_SCAN,
                    src_ip=ip,
                    severity=Severity.HIGH,
                    evidence_events=list(window),
                    detector="rule_based",
                    notes=f"{len(distinct_ports)} distinct ports probed within {window_minutes} minutes",
                    extra={"ports": sorted(distinct_ports)},
                ))
                window = []
    return incidents


def detect_directory_enumeration(events: list[LogEvent], threshold: int = 10,
                                  window_minutes: int = 5) -> list[Incident]:
    """Flag an IP generating a burst of 404s against a web server, a common
    signature of automated directory/endpoint brute forcing tools."""
    web_404s = [e for e in events
            if e.source == LogSource.WEB_ACCESS
            and e.status_code in (403, 404)
            and e.src_ip and e.timestamp]

    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in web_404s:
        by_ip[e.src_ip].append(e)

    incidents = []
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        window = []
        for e in ip_events:
            window.append(e)
            window = [w for w in window if e.timestamp - w.timestamp <= timedelta(minutes=window_minutes)]
            if len(window) >= threshold:
                incidents.append(Incident(
                    incident_type=IncidentType.DIR_ENUMERATION,
                    src_ip=ip,
                    severity=Severity.MEDIUM,
                    evidence_events=list(window),
                    detector="rule_based",
                    notes=f"{len(window)} 404 responses within {window_minutes} minutes",
                ))
                window = []
    return incidents


# ---------------------------------------------------------------------------
# ML-based detector: Isolation Forest over per-IP behavioral features
# ---------------------------------------------------------------------------

def _build_ip_feature_matrix(events: list[LogEvent]) -> tuple[list[str], np.ndarray]:
    """Engineer a small feature vector per source IP describing its overall
    behavior across all log sources. Isolation Forest then learns what
    'normal' looks like across the population of IPs and flags outliers."""
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.src_ip:
            by_ip[e.src_ip].append(e)

    ips = list(by_ip.keys())
    rows = []
    for ip in ips:
        ip_events = by_ip[ip]
        total = len(ip_events)
        failed_logins = sum(1 for e in ip_events if e.action in ("failed_password", "invalid_user"))
        distinct_ports = len({e.target for e in ip_events if e.source == LogSource.FIREWALL and e.target})
        error_responses = sum(1 for e in ip_events if e.status_code and e.status_code >= 400)
        distinct_paths = len({e.target for e in ip_events if e.source == LogSource.WEB_ACCESS and e.target})
        rows.append([total, failed_logins, distinct_ports, error_responses, distinct_paths])

    return ips, np.array(rows, dtype=float)


def detect_statistical_anomalies(events: list[LogEvent], contamination: float = 0.1) -> list[Incident]:
    """Run Isolation Forest over per-IP behavioral feature vectors.
    `contamination` is the expected proportion of outlier IPs and is the
    main knob to tune precision/recall trade-off in production."""
    ips, X = _build_ip_feature_matrix(events)

    if len(ips) < 3:
        return []  # not enough IPs to model a meaningful distribution

    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(X)          # -1 = anomaly, 1 = normal
    scores = model.decision_function(X)         # lower = more anomalous

    incidents = []
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.src_ip:
            by_ip[e.src_ip].append(e)

    for ip, pred, score in zip(ips, predictions, scores):
        if pred == -1:
            confidence = float(np.clip(1 - (score + 0.5), 0.0, 1.0))
            severity = Severity.HIGH if confidence > 0.7 else Severity.MEDIUM
            incidents.append(Incident(
                incident_type=IncidentType.STATISTICAL_ANOMALY,
                src_ip=ip,
                severity=severity,
                evidence_events=by_ip[ip][:20],  # cap evidence size for readability
                detector="isolation_forest",
                confidence=confidence,
                notes="Behavioral profile statistically deviates from baseline traffic",
            ))
    return incidents


def run_all_detectors(events: list[LogEvent]) -> list[Incident]:
    incidents = []
    incidents += detect_brute_force(events)
    incidents += detect_port_scan(events)
    incidents += detect_directory_enumeration(events)
    incidents += detect_statistical_anomalies(events)
    return incidents
