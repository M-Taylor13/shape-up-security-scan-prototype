# Temporary severity criteria

SEVERITY_ACTIONS = {
    "CRITICAL": "FAIL",
    "HIGH": "FAIL",
    "ERROR": "FAIL",
    "MEDIUM": "WARN",
    "WARNING": "WARN",
    "LOW": "PASS",
    "INFO": "PASS",
}


def get_action(severity: str) -> str:
    """Convert scanner severity into our project status."""

    severity = severity.upper()

    return SEVERITY_ACTIONS.get(severity, "WARN")