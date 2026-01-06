import psutil
import os


SUSPICIOUS_PATHS = [
    "appdata",
    "temp",
    "downloads",
    "public"
]


def is_suspicious_path(path: str) -> bool:
    path = path.lower()
    return any(p in path for p in SUSPICIOUS_PATHS)


def analyze_processes() -> list:
    findings = []

    for proc in psutil.process_iter(attrs=[
        "pid", "name", "exe", "ppid", "cpu_percent", "memory_info"
    ]):
        try:
            info = proc.info
            exe = info.get("exe") or ""
            name = info.get("name") or "unknown"
            pid = info.get("pid")
            ppid = info.get("ppid")
            cpu = info.get("cpu_percent", 0)

            # Suspicious execution path
            if exe and is_suspicious_path(exe):
                findings.append({
                    "category": "process",
                    "severity": "medium",
                    "description": f"Process {name} (PID {pid}) running from suspicious path: {exe}",
                    "confidence": 0.7
                })

            # No parent process (orphan)
            if ppid == 0:
                findings.append({
                    "category": "process",
                    "severity": "high",
                    "description": f"Process {name} (PID {pid}) has no parent process",
                    "confidence": 0.8
                })

            # Headless but active
            if cpu > 5 and not exe.lower().startswith("c:\\windows"):
                findings.append({
                    "category": "process",
                    "severity": "medium",
                    "description": f"Process {name} (PID {pid}) consuming CPU without GUI",
                    "confidence": 0.6
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return findings


def run():
    print("[*] Process scan started...")
    findings = analyze_processes()
    print(f"[!] Process findings: {len(findings)}")
    return findings


if __name__ == "__main__":
    results = run()
    for r in results:
        print(r)
