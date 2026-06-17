import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.log_parser import parse_line, LogSource, parsing_coverage


def test_parses_ssh_failed_password():
    line = "Jun 14 02:11:08 server sshd[1234]: Failed password for root from 192.168.1.50 port 51514 ssh2"
    event = parse_line(line)
    assert event.parsed_ok
    assert event.source == LogSource.SSH_AUTH
    assert event.src_ip == "192.168.1.50"
    assert event.action == "failed_password"
    assert event.user == "root"


def test_parses_web_access_log():
    line = '203.0.113.5 - - [14/Jun/2026:02:11:09 +0000] "GET /admin/config.php HTTP/1.1" 404 512'
    event = parse_line(line)
    assert event.parsed_ok
    assert event.source == LogSource.WEB_ACCESS
    assert event.status_code == 404
    assert event.target == "/admin/config.php"


def test_parses_firewall_log():
    line = "Jun 14 02:11:10 fw kernel: IN=eth0 SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP DPT=22 ACTION=DENY"
    event = parse_line(line)
    assert event.parsed_ok
    assert event.source == LogSource.FIREWALL
    assert event.src_ip == "198.51.100.7"
    assert event.action == "DENY"


def test_unparseable_line_returns_unparsed_event():
    event = parse_line("this is not a real log line at all")
    assert not event.parsed_ok
    assert event.source == LogSource.UNKNOWN


def test_parsing_coverage_metric():
    lines = [
        "Jun 14 02:11:08 server sshd[1234]: Failed password for root from 192.168.1.50 port 51514 ssh2",
        "garbage line",
    ]
    events = [parse_line(l) for l in lines]
    assert parsing_coverage(events) == 0.5
