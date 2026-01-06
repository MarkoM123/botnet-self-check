import os
import subprocess
import winreg
import datetime


def scan_hosts_file():
    findings = []
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                findings.append({
                    "category": "system",
                    "severity": "medium",
                    "description": f"Hosts file entry detected: {line}",
                    "confidence": 0.7
                })
    except Exception:
        pass

    return findings


def scan_proxy_settings():
    findings = []
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        proxy_enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")

        if proxy_enabled:
            findings.append({
                "category": "system",
                "severity": "medium",
                "description": f"System proxy enabled: {proxy_server}",
                "confidence": 0.8
            })
    except Exception:
        pass

    return findings


def scan_firewall_rules():
    findings = []
    try:
        output = subprocess.check_output(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            text=True,
            errors="ignore"
        )

        for block in output.split("\n\n"):
            if "Direction:                            Out" in block and "Allow" in block:
                for line in block.splitlines():
                    if "Rule Name:" in line:
                        name = line.split(":", 1)[1].strip()
                        findings.append({
                            "category": "system",
                            "severity": "low",
                            "description": f"Outbound firewall allow rule: {name}",
                            "confidence": 0.4
                        })
    except Exception:
        pass

    return findings


def scan_time_skew():
    findings = []
    try:
        now = datetime.datetime.now()
        utc = datetime.datetime.utcnow()
        diff = abs((now - utc).total_seconds()) / 3600

        if diff > 2:
            findings.append({
                "category": "system",
                "severity": "medium",
                "description": f"System time differs from UTC by {round(diff,2)} hours",
                "confidence": 0.6
            })
    except Exception:
        pass

    return findings


def scan_defender_status():
    findings = []
    try:
        output = subprocess.check_output(
            ["powershell", "-Command", "Get-MpComputerStatus | Select AMServiceEnabled"],
            text=True,
            errors="ignore"
        )

        if "False" in output:
            findings.append({
                "category": "system",
                "severity": "high",
                "description": "Windows Defender appears to be disabled",
                "confidence": 0.9
            })
    except Exception:
        pass

    return findings


def run():
    print("[*] System scan started...")

    findings = []
    findings += scan_hosts_file()
    findings += scan_proxy_settings()
    findings += scan_firewall_rules()
    findings += scan_time_skew()
    findings += scan_defender_status()

    print(f"[!] System findings: {len(findings)}")
    return findings


if __name__ == "__main__":
    results = run()
    for r in results:
        print(r)
