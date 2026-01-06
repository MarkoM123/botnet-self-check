import winreg
import os
import subprocess
import psutil


RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def scan_registry_autoruns():
    findings = []

    for hive, path in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                findings.append({
                    "category": "persistence",
                    "severity": "high",
                    "description": f"Autorun registry entry: {name} -> {value}",
                    "confidence": 0.9
                })
                i += 1
        except OSError:
            pass

    return findings


def scan_startup_folder():
    findings = []
    startup_dirs = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]

    for folder in startup_dirs:
        if os.path.exists(folder):
            for f in os.listdir(folder):
                findings.append({
                    "category": "persistence",
                    "severity": "high",
                    "description": f"Startup folder item detected: {folder}\\{f}",
                    "confidence": 0.85
                })

    return findings


def scan_scheduled_tasks():
    findings = []
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            text=True,
            errors="ignore"
        )

        for block in output.split("\n\n"):
            if "Task To Run:" in block and "System32" not in block:
                for line in block.splitlines():
                    if "Task To Run:" in line:
                        task = line.split(":", 1)[1].strip()
                        findings.append({
                            "category": "persistence",
                            "severity": "high",
                            "description": f"Scheduled task with custom binary: {task}",
                            "confidence": 0.9
                        })
    except Exception:
        pass

    return findings


def scan_services():
    findings = []

    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
            if info["start_type"] == "auto" and "windows" not in info["binpath"].lower():
                findings.append({
                    "category": "persistence",
                    "severity": "high",
                    "description": f"Auto-start service: {info['name']} -> {info['binpath']}",
                    "confidence": 0.9
                })
        except Exception:
            continue

    return findings


def run():
    print("[*] Persistence scan started...")

    findings = []
    findings += scan_registry_autoruns()
    findings += scan_startup_folder()
    findings += scan_scheduled_tasks()
    findings += scan_services()

    print(f"[!] Persistence findings: {len(findings)}")
    return findings


if __name__ == "__main__":
    results = run()
    for r in results:
        print(r)
