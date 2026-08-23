# scanner/classifier.py

CATEGORY_PATTERNS = {
    "SQL Injection": [
        "sql-injection",
        "sql_injection",
        "sqlalchemy-execute-raw-query",
        "raw-query",
        "sqli",
    ],

    "Cross-Site Scripting (XSS)": [
        "xss",
        "cross-site-scripting",
        "raw-html",
        "unsafe-html",
        "markup",
    ],

    "Command Injection": [
        "command-injection",
        "command_injection",
        "os-command",
        "shell-injection",
    ],

    "Path Traversal": [
        "path-traversal",
        "directory-traversal",
    ],

    "Hardcoded Secret": [
        "hardcoded-secret",
        "hardcoded-password",
        "api-key",
        "access-token",
    ],
}


def classify_rule(rule_id: str, message: str = "", metadata: str = "") -> str:
    """
    Convert scanner-specific rule names into broad,
    user-friendly vulnerability categories.
    """

    searchable = f"{rule_id} {message}".lower()

    for category, patterns in CATEGORY_PATTERNS.items():
        if any(pattern in searchable for pattern in patterns):
            return category

    return "Other Security Issue"