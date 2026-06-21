import random
from datetime import datetime, timedelta

random.seed(42)
base_time = datetime(2024, 6, 15, 2, 0, 0)

normal_ips = [f"10.0.0.{i}" for i in range(1, 20)]
normal_users = ["alice", "bob", "charlie", "diana", "eve"]

# ─── AUTH.LOG ────────────────────────────────────────────────────
ssh_lines = []
for _ in range(120):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    user = random.choice(normal_users)
    action = random.choices(["Accepted", "Failed"], weights=[85, 15])[0]
    ssh_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: {action} password for {user} from {ip} port {random.randint(1024,65535)} ssh2"))

# Brute force: 198.51.100.7, 7 failures within 10 min window (threshold=5)
atk_time = base_time + timedelta(minutes=30)
for i in range(7):
    t = atk_time + timedelta(seconds=i * 20)
    ssh_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: Failed password for root from 198.51.100.7 port 22 ssh2"))

ssh_lines.sort(key=lambda x: x[0])
with open("/home/claude/fixed_logs/auth.log", "w") as f:
    f.write("\n".join(line for _, line in ssh_lines))
print(f"auth.log: {len(ssh_lines)} lines")

# ─── ACCESS.LOG ──────────────────────────────────────────────────
web_lines = []
normal_paths = ["/", "/index.html", "/about", "/contact", "/products", "/blog", "/login", "/api/v1/status"]
sensitive_paths = ["/.env", "/admin", "/.git/config", "/config.php", "/backup.zip", "/wp-admin", "/phpmyadmin", "/.htaccess", "/server-status", "/old", "/test", "/secret"]

for _ in range(200):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    method = random.choices(["GET", "POST"], weights=[80, 20])[0]
    path = random.choice(normal_paths)
    status = random.choices([200, 301], weights=[90, 10])[0]
    size = random.randint(200, 8000)
    web_lines.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size}'))

# Directory enumeration: 198.51.100.7, 12 distinct 404s within 5 min (threshold=10)
enum_time = base_time + timedelta(minutes=60)
for i, path in enumerate(sensitive_paths):
    t = enum_time + timedelta(seconds=i * 15)  # 12 hits across 165s, well under 5 min
    web_lines.append((t, f'198.51.100.7 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" 404 287'))

web_lines.sort(key=lambda x: x[0])
with open("/home/claude/fixed_logs/access.log", "w") as f:
    f.write("\n".join(line for _, line in web_lines))
print(f"access.log: {len(web_lines)} lines")

# ─── FIREWALL.LOG (already passing — keep as-is, but regenerate consistently) ──
fw_lines = []
for _ in range(150):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    dport = random.choice([80, 443, 22, 3306, 5432])
    action = random.choices(["ACCEPT", "DROP"], weights=[80, 20])[0]
    fw_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} kernel: {action} IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={random.randint(1024,65535)} DPT={dport}"))

# Port scan: 192.0.2.88, 9 distinct ports within 5 min (threshold=8)
scan_time = base_time + timedelta(minutes=90)
scan_ports = [21,22,23,25,53,80,443,3389,8080]
for i, port in enumerate(scan_ports):
    t = scan_time + timedelta(seconds=i * 5)
    fw_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} kernel: DROP IN=eth0 OUT= SRC=192.0.2.88 DST=192.168.1.1 PROTO=TCP SPT=44823 DPT={port}"))

fw_lines.sort(key=lambda x: x[0])
with open("/home/claude/fixed_logs/firewall.log", "w") as f:
    f.write("\n".join(line for _, line in fw_lines))
print(f"firewall.log: {len(fw_lines)} lines")