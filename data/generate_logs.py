import random
from datetime import datetime, timedelta
import os

random.seed(42)
base_time = datetime(2024, 6, 15, 2, 0, 0)
os.makedirs("sample_logs", exist_ok=True)

# ─── SSH AUTH LOG ───────────────────────────────────────────────
ssh_lines = []

# Normal users
normal_ips = [f"10.0.0.{i}" for i in range(1, 20)]
normal_users = ["alice", "bob", "charlie", "diana", "eve"]

for _ in range(120):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    user = random.choice(normal_users)
    action = random.choices(["Accepted", "Failed"], weights=[85, 15])[0]
    ssh_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: {action} password for {user} from {ip} port {random.randint(1024,65535)} ssh2"))

# Brute force attack from 192.168.1.105
atk_time = base_time + timedelta(minutes=30)
for i in range(52):
    t = atk_time + timedelta(seconds=i * 2)
    ssh_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2"))

# One successful login from attacker after brute force
t = atk_time + timedelta(seconds=110)
ssh_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: Accepted password for root from 192.168.1.105 port 22 ssh2"))

ssh_lines.sort(key=lambda x: x[0])
with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(line for _, line in ssh_lines))
print(f"auth.log: {len(ssh_lines)} lines")

# ─── WEB ACCESS LOG ─────────────────────────────────────────────
web_lines = []

normal_paths = ["/", "/index.html", "/about", "/contact", "/products", "/blog", "/login", "/api/v1/status"]
sensitive_paths = ["/.env", "/admin", "/.git/config", "/config.php", "/backup.zip", "/wp-admin", "/phpmyadmin", "/.htaccess", "/server-status"]

# Normal web traffic
for _ in range(200):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    method = random.choices(["GET", "POST"], weights=[80, 20])[0]
    path = random.choice(normal_paths)
    status = random.choices([200, 301, 404], weights=[85, 10, 5])[0]
    size = random.randint(200, 8000)
    web_lines.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size}'))

# Directory enumeration from 10.0.0.99
enum_time = base_time + timedelta(minutes=60)
for i, path in enumerate(sensitive_paths * 2):
    t = enum_time + timedelta(seconds=i * 3)
    status = random.choice([403, 404])
    web_lines.append((t, f'10.0.0.99 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" {status} 287'))

# Some 200s mixed in (successful finds)
for i, path in enumerate(["/admin", "/.env"]):
    t = enum_time + timedelta(seconds=100 + i * 5)
    web_lines.append((t, f'10.0.0.99 - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET {path} HTTP/1.1" 200 1452'))

web_lines.sort(key=lambda x: x[0])
with open("sample_logs/access.log", "w") as f:
    f.write("\n".join(line for _, line in web_lines))
print(f"access.log: {len(web_lines)} lines")

# ─── FIREWALL LOG ───────────────────────────────────────────────
fw_lines = []

# Normal traffic
for _ in range(150):
    t = base_time + timedelta(seconds=random.randint(0, 7200))
    ip = random.choice(normal_ips)
    dport = random.choice([80, 443, 22, 3306, 5432])
    action = random.choices(["ACCEPT", "DROP"], weights=[80, 20])[0]
    fw_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} kernel: {action} IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={random.randint(1024,65535)} DPT={dport}"))

# Port scan from 172.16.0.50
scan_time = base_time + timedelta(minutes=90)
scan_ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017,6443]
for i, port in enumerate(scan_ports):
    t = scan_time + timedelta(seconds=i)
    fw_lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} kernel: DROP IN=eth0 OUT= SRC=172.16.0.50 DST=192.168.1.1 PROTO=TCP SPT=44823 DPT={port}"))

fw_lines.sort(key=lambda x: x[0])
with open("sample_logs/firewall.log", "w") as f:
    f.write("\n".join(line for _, line in fw_lines))
print(f"firewall.log: {len(fw_lines)} lines")

print("\nDone! Files saved to sample_logs/")