# Parse scanner output into dashboard-readable statistics
import json
from pathlib import Path

from criteria import get_action


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def load_json(filename, default):
    path = RESULTS / filename

    if not path.exists():
        return default

    try:
        with open(path, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        return default


def process_semgrep():

    data = load_json(
        "semgrep.json",
        {"results": []}
    )

    findings = []

    for result in data.get("results", []):

        extra = result.get("extra", {})

        severity = extra.get(
            "severity",
            "INFO"
        ).upper()

        findings.append({
            "scanner": "Semgrep",
            "type": "SAST",
            "category": result.get(
                "check_id",
                "Unknown"
            ),
            "severity": severity,
            "status": get_action(severity),
            "file": result.get(
                "path",
                "Unknown"
            ),
            "line": result.get(
                "start",
                {}
            ).get("line"),
            "message": extra.get(
                "message",
                "No description available."
            )
        })

    return findings


def process_gitleaks():

    data = load_json(
        "gitleaks.json",
        []
    )

    findings = []

    for result in data:

        findings.append({
            "scanner": "Gitleaks",
            "type": "SECRET",
            "category": result.get(
                "RuleID",
                "Secret detected"
            ),
            "severity": "CRITICAL",
            "status": "FAIL",
            "file": result.get(
                "File",
                "Unknown"
            ),
            "line": result.get(
                "StartLine"
            ),
            "message": result.get(
                "Description",
                "Potential secret detected."
            )
        })

    return findings


def process_pip_audit():
    data = load_json("pip-audit.json", {"dependencies": []})
    findings = []

    for dep in data.get("dependencies", []):
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            # Use 'fix_versions' to construct remediation advice
            fixes = vuln.get("fix_versions", [])
            fix_str = f" Fix by upgrading to {', '.join(fixes)}." if fixes else ""

            findings.append({
                "scanner": "pip-audit",
                "type": "SCA",
                "category": vuln.get("id", "Vulnerability"),
                "severity": "HIGH",  # pip-audit json doesn't always have severity, default to HIGH
                "status": "FAIL",
                "file": dep.get("name", "Unknown Package"),
                "line": dep.get("version", "Unknown Version"),
                "message": vuln.get("description", "Vulnerable dependency detected.") + fix_str
            })

    return findings


def filter_ignored_findings(findings):
    ignore_file = ROOT / ".scannerignore"
    if not ignore_file.exists():
        return findings

    with open(ignore_file, "r") as f:
        ignored_patterns = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    filtered = []
    for finding in findings:
        drop = False
        for pattern in ignored_patterns:
            if pattern in finding.get("category", "") or pattern in finding.get("file", ""):
                drop = True
                break
        
        if not drop:
            filtered.append(finding)
            
    return filtered


def build_report():
    import datetime

    findings = []

    findings.extend(process_semgrep())
    findings.extend(process_gitleaks())
    findings.extend(process_pip_audit())
    
    findings = filter_ignored_findings(findings)

    failed = sum(1 for f in findings if f["status"] == "FAIL")
    warnings = sum(1 for f in findings if f["status"] == "WARN")
    passed = sum(1 for f in findings if f["status"] == "PASS")

    status = "FAIL" if failed > 0 else "PASS"

    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "status": status,
        "summary": {
            "passed": passed,
            "failed": failed,
            "warnings": warnings
        },
        "findings": findings
    }

    with open(RESULTS / "results.json", "w") as file:
        json.dump(report, file, indent=2)
        
    # Save historical trending data
    history_dir = RESULTS / "history"
    history_dir.mkdir(exist_ok=True)
    
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    history_file = history_dir / f"scan_{timestamp_str}.json"
    
    with open(history_file, "w") as file:
        json.dump(report, file, indent=2)

    print(
        f"Security scan: {status} "
        f"({passed} passed, "
        f"{warnings} warnings, "
        f"{failed} failed)"
    )


if __name__ == "__main__":
    build_report()