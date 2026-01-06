import json
import os
from datetime import datetime

from scanner.network_scan import run as network_scan
from scanner.dns_scan import run as dns_scan
from scanner.process_scan import run as process_scan
from scanner.persistence_scan import run as persistence_scan
from scanner.system_scan import run as system_scan

from scoring.risk_engine import calculate_risk


OUTPUT_DIR = "output"


def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def run_all_scans():
    all_findings = []

    print("\n=== BOTNET SELF CHECK ===\n")

    all_findings += network_scan()
    all_findings += dns_scan()
    all_findings += process_scan()
    all_findings += persistence_scan()
    all_findings += system_scan()

    return all_findings


def print_report(risk_result: dict):
    print("\n==============================")
    print("       RISK ASSESSMENT")
    print("==============================")
    print(f"RISK SCORE : {risk_result['risk_score']} / 100")
    print(f"RISK LEVEL : {risk_result['risk_level']}")
    print("\nReasons:")
    for r in risk_result["reasons"]:
        print(f" - {r}")
    print("==============================\n")


def save_report(findings: list, risk_result: dict):
    ensure_output_dir()

    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "risk": risk_result
    }

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(OUTPUT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved to {path}")


def main():
    findings = run_all_scans()

    if not findings:
        print("No suspicious activity detected.")
        return

    risk_result = calculate_risk(findings)

    print_report(risk_result)
    save_report(findings, risk_result)


if __name__ == "__main__":
    main()
