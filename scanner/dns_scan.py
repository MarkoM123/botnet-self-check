import subprocess
import re
import math
from collections import defaultdict


def shannon_entropy(s: str) -> float:
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)

    return entropy


def get_dns_cache():
    output = subprocess.check_output(
        ["ipconfig", "/displaydns"],
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    domains = []
    for line in output.splitlines():
        if "Record Name" in line:
            domain = line.split(":")[-1].strip()
            domains.append(domain.lower())

    return domains


def analyze_dns(domains: list) -> list:
    findings = []
    domain_counter = defaultdict(int)

    for d in domains:
        domain_counter[d] += 1

    for domain, count in domain_counter.items():
        sub = domain.split(".")[0]

        # Rare domain
        if count <= 2:
            findings.append({
                "category": "dns",
                "severity": "medium",
                "description": f"Rare DNS domain queried: {domain}",
                "confidence": 0.6
            })

        # High entropy subdomain (DGA-like)
        entropy = shannon_entropy(sub)
        if entropy > 3.8 and len(sub) > 8:
            findings.append({
                "category": "dns",
                "severity": "high",
                "description": f"High entropy subdomain detected: {domain}",
                "confidence": 0.85
            })

    return findings


def run():
    print("[*] DNS scan started...")
    domains = get_dns_cache()
    print(f"[*] Collected {len(domains)} DNS entries")

    findings = analyze_dns(domains)
    print(f"[!] DNS findings: {len(findings)}")

    return findings


if __name__ == "__main__":
    results = run()
    for r in results:
        print(r)
