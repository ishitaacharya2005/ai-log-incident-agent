import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.log_parser import parse_log_file
from app.core.anomaly_detector import (
    detect_brute_force,
    detect_port_scan,
    detect_directory_enumeration,
    run_all_detectors,
)

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "data" / "sample_logs"


def _load_all_sample_events():
    events = []
    for log_file in SAMPLE_DIR.glob("*.log"):
        events += parse_log_file(str(log_file))
    return events


def test_brute_force_detected_in_sample_auth_log():
    events = parse_log_file(str(SAMPLE_DIR / "auth.log"))
    incidents = detect_brute_force(events, threshold=5, window_minutes=10)
    assert len(incidents) >= 1
    assert incidents[0].src_ip == "198.51.100.7"


def test_port_scan_detected_in_sample_firewall_log():
    events = parse_log_file(str(SAMPLE_DIR / "firewall.log"))
    incidents = detect_port_scan(events, distinct_ports_threshold=8, window_minutes=5)
    assert len(incidents) >= 1
    assert incidents[0].src_ip == "192.0.2.88"


def test_directory_enumeration_detected_in_sample_web_log():
    events = parse_log_file(str(SAMPLE_DIR / "access.log"))
    incidents = detect_directory_enumeration(events, threshold=10, window_minutes=5)
    assert len(incidents) >= 1
    assert incidents[0].src_ip == "198.51.100.7"


def test_run_all_detectors_returns_combined_incidents():
    events = _load_all_sample_events()
    incidents = run_all_detectors(events)
    incident_types = {i.incident_type.value for i in incidents}
    assert "brute_force_login_attempt" in incident_types
    assert "port_scan" in incident_types
    assert "directory_enumeration" in incident_types


def test_no_false_positive_on_benign_traffic():
    from app.core.log_parser import parse_line
    benign = [
        parse_line("Jun 14 02:10:01 server sshd[1001]: Accepted password for deploy from 10.0.0.15 port 51200 ssh2"),
        parse_line('10.0.0.15 - - [14/Jun/2026:02:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024'),
    ]
    incidents = detect_brute_force(benign) + detect_directory_enumeration(benign)
    assert len(incidents) == 0
