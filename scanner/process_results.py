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


def build_report():

    findings = []

    findings.extend(process_semgrep())
    findings.extend(process_gitleaks())

    failed = sum(
        finding["status"] == "FAIL"
        for finding in findings
    )

    warnings = sum(
        finding["status"] == "WARN"
        for finding in findings
    )

    passed = sum(
        finding["status"] == "PASS"
        for finding in findings
    )

    status = "FAIL" if failed > 0 else "PASS"

    report = {
        "status": status,
        "summary": {
            "passed": passed,
            "failed": failed,
            "warnings": warnings
        },
        "findings": findings
    }

    with open(
        RESULTS / "results.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=2
        )

    print(
        f"Security scan: {status} "
        f"({passed} passed, "
        f"{warnings} warnings, "
        f"{failed} failed)"
    )


if __name__ == "__main__":
    build_report()