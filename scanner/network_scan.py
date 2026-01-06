import psutil
import time
from collections import defaultdict

SCAN_DURATION = 30  # seconds
BEACON_THRESHOLD = 5  # connections
RARE_IP_THRESHOLD = 3  # occurrences


def collect_connections(duration: int):
    connections = []
    start = time.time()

    while time.time() - start < duration:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.status == psutil.CONN_ESTABLISHED:
                connections.append({
                    "pid": c.pid,
                    "laddr": c.laddr.ip,
                    "raddr": c.raddr.ip,
                    "rport": c.raddr.port,
                    "timestamp": time.time()
                })
        time.sleep(1)

    return connections


def analyze_connections(connections: list) -> list:
    findings = []

    ip_counter = defaultdict(int)
    pid_counter = defaultdict(list)

    for c in connections:
        ip_counter[c["raddr"]] += 1
        pid_counter[c["pid"]].append(c)

    # Rare outbound IPs
    for ip, count in ip_counter.items():
        if count <= RARE_IP_THRESHOLD:
            findings.append({
                "category": "network",
                "severity": "medium",
                "description": f"Outbound connection to rare IP {ip}",
                "confidence": 0.6
            })

    # Beaconing detection
    for pid, conns in pid_counter.items():
        if len(conns) >= BEACON_THRESHOLD:
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
            except Exception:
                pname = "unknown"

            findings.append({
                "category": "network",
                "severity": "high",
                "description": f"Process {pname} (PID {pid}) opened {len(conns)} outbound connections",
                "confidence": 0.8
            })

    return findings


def run():
    print("[*] Network scan started...")
    connections = collect_connections(SCAN_DURATION)
    print(f"[*] Collected {len(connections)} connections")

    findings = analyze_connections(connections)
    print(f"[!] Network findings: {len(findings)}")

    return findings


if __name__ == "__main__":
    results = run()
    for r in results:
        print(r)
