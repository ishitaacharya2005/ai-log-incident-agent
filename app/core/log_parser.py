"""
log_parser.py
--------------
Converts raw, heterogeneous log lines (SSH/auth logs, web server access logs,
firewall logs) into a single structured representation (LogEvent) that the
rest of the pipeline (anomaly detector, LLM triage agent) can reason over.

Design notes:
- Each log source has its own regex-based extractor instead of one giant
  regex, because real-world log formats diverge a lot and a monolithic
  pattern becomes unmaintainable and silently swallows malformed lines.
- Lines that don't match any known pattern are not dropped silently; they
  are returned as UNPARSED events so nothing is lost and parsing coverage
  can be measured (useful to mention in an interview: "what % of lines
  did your parser successfully structure?").
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class LogSource(str, Enum):
    SSH_AUTH = "ssh_auth"
    WEB_ACCESS = "web_access"
    FIREWALL = "firewall"
    UNKNOWN = "unknown"


@dataclass
class LogEvent:
    raw_line: str
    source: LogSource
    timestamp: Optional[datetime]
    src_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None          # e.g. "failed_password", "GET", "DENY"
    target: Optional[str] = None          # e.g. requested URL, destination port
    status_code: Optional[int] = None
    extra: dict = field(default_factory=dict)
    parsed_ok: bool = True


# ---------------------------------------------------------------------------
# SSH / auth.log style entries
# e.g. "Jun 14 02:11:08 server sshd[1234]: Failed password for root from
#       192.168.1.50 port 51514 ssh2"
# ---------------------------------------------------------------------------
_SSH_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<action>Failed password|Accepted password|Invalid user|Connection closed)"
    r"(?:\s+for\s+(?:invalid user\s+)?(?P<user>\S+))?"
    r"(?:\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?"
    r"(?:\s+port\s+(?P<port>\d+))?"
)

# ---------------------------------------------------------------------------
# Web server access log (Combined Log Format)
# e.g. '203.0.113.5 - - [14/Jun/2026:02:11:09 +0000] "GET /admin/config.php
#       HTTP/1.1" 404 512'
# ---------------------------------------------------------------------------
_WEB_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\["
    r"(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+)"
)

# ---------------------------------------------------------------------------
# Firewall log (simplified iptables-style)
# e.g. "Jun 14 02:11:10 fw kernel: IN=eth0 SRC=198.51.100.7 DST=10.0.0.5
#       PROTO=TCP DPT=22 ACTION=DENY"
# ---------------------------------------------------------------------------
_FIREWALL_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*"
    r"SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"PROTO=(?P<proto>\w+)\s+DPT=(?P<dport>\d+)\s+"
    r"ACTION=(?P<action>\w+)"
)

_SYSLOG_YEAR_FALLBACK = datetime.now().year


def _parse_syslog_timestamp(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(f"{ts} {_SYSLOG_YEAR_FALLBACK}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def _parse_clf_timestamp(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


def parse_line(line: str) -> LogEvent:
    """Attempt to parse a single raw log line against known formats in order
    of specificity. Returns an UNPARSED LogEvent if nothing matches."""

    line = line.rstrip("\n")

    m = _SSH_PATTERN.search(line)
    if m:
        return LogEvent(
            raw_line=line,
            source=LogSource.SSH_AUTH,
            timestamp=_parse_syslog_timestamp(m.group("timestamp")),
            src_ip=m.group("ip"),
            user=m.group("user"),
            action=m.group("action").lower().replace(" ", "_"),
            target=m.group("port"),
        )

    m = _WEB_PATTERN.search(line)
    if m:
        return LogEvent(
            raw_line=line,
            source=LogSource.WEB_ACCESS,
            timestamp=_parse_clf_timestamp(m.group("timestamp")),
            src_ip=m.group("ip"),
            action=m.group("method"),
            target=m.group("path"),
            status_code=int(m.group("status")),
            extra={"response_size": int(m.group("size"))},
        )

    m = _FIREWALL_PATTERN.search(line)
    if m:
        return LogEvent(
            raw_line=line,
            source=LogSource.FIREWALL,
            timestamp=_parse_syslog_timestamp(m.group("timestamp")),
            src_ip=m.group("src"),
            action=m.group("action"),
            target=m.group("dport"),
            extra={"dst_ip": m.group("dst"), "protocol": m.group("proto")},
        )

    return LogEvent(
        raw_line=line,
        source=LogSource.UNKNOWN,
        timestamp=None,
        parsed_ok=False,
    )


def parse_log_file(path: str) -> list[LogEvent]:
    events = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if line.strip():
                events.append(parse_line(line))
    return events


def parsing_coverage(events: list[LogEvent]) -> float:
    """Fraction of lines that were successfully structured. Worth reporting
    in the README/resume as a concrete metric rather than a vague claim."""
    if not events:
        return 0.0
    return sum(1 for e in events if e.parsed_ok) / len(events)
