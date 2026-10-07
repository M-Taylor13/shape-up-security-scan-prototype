# Parse scanner output into dashboard-readable statistics
import json
from pathlib import Path

from criteria import get_action


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def get_plain_language_description(scanner, category, original_message):
    plain_desc = ""
    
    category_lower = category.lower()
    msg_lower = original_message.lower()

    if scanner == "Semgrep":
        if "sql" in category_lower or "sql" in msg_lower:
            plain_desc = "SQL Injection: The code allows external input to manipulate database queries, which could let hackers view or delete private data."
        elif "xss" in category_lower or "xss" in msg_lower:
            plain_desc = "Cross-Site Scripting (XSS): The code allows malicious scripts to be injected into webpages viewed by other users."
        elif "secret" in category_lower or "password" in msg_lower or "token" in msg_lower or "key" in category_lower:
            plain_desc = "Hardcoded Secret: A password, API key, or token is written directly in the code. Hackers can easily find this and use it to access your systems."
        elif "exec" in category_lower or "command" in msg_lower:
            plain_desc = "Command Injection: The code runs system commands using external input, which could let hackers take control of the server."
        else:
            plain_desc = "Code Security Issue: A potential vulnerability was found in how this code is written."
            
    elif scanner == "OSV-Scanner":
        if "dos" in msg_lower or "denial of service" in msg_lower:
            plain_desc = "Denial of Service (DoS): This package has a flaw that could allow hackers to crash the application by overwhelming it."
        elif "execution" in msg_lower or "rce" in msg_lower:
            plain_desc = "Remote Code Execution (RCE): This package has a critical flaw that could allow hackers to run malicious code on your server."
        else:
            plain_desc = "Outdated Package: This third-party package contains a publicly known security flaw. Hackers can use this flaw to attack your application."

    elif scanner == "Gitleaks":
        plain_desc = "Leaked Secret: A sensitive credential (like a password or API key) was found in your files. If committed, anyone with access to the codebase can see it."

    elif scanner == "Bandit":
        cat_lower = category.lower()
        if "subprocess" in cat_lower or "b602" in cat_lower or "b603" in cat_lower:
            plain_desc = "Shell Injection Risk: The code runs a system command using shell=True or with unsanitised input. An attacker who controls that input could run arbitrary commands on the server."
        elif "md5" in cat_lower or "sha1" in cat_lower or "b303" in cat_lower or "b324" in cat_lower:
            plain_desc = "Weak Cryptography: The code uses an outdated hashing algorithm (MD5 or SHA1) that is no longer considered secure for passwords or sensitive data. Use SHA-256 or bcrypt instead."
        elif "random" in cat_lower or "b311" in cat_lower:
            plain_desc = "Insecure Randomness: The code uses Python's standard `random` module for a security-sensitive purpose (e.g. tokens or passwords). Use `secrets` or `os.urandom()` instead, which are cryptographically secure."
        elif "pickle" in cat_lower or "b301" in cat_lower or "b302" in cat_lower:
            plain_desc = "Unsafe Deserialization: The code uses `pickle` to load data. If the data comes from an untrusted source, an attacker can craft a malicious payload that executes arbitrary code when unpickled."
        elif "tempfile" in cat_lower or "b108" in cat_lower:
            plain_desc = "Insecure Temp File: The code creates a temporary file using an insecure method that is vulnerable to race conditions. Use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` instead."
        elif "password" in cat_lower or "b105" in cat_lower or "b106" in cat_lower or "b107" in cat_lower:
            plain_desc = "Hardcoded Password: A password or secret is written directly in the source code. Anyone with access to the code can read it. Use environment variables or a secrets manager instead."
        elif "assert" in cat_lower or "b101" in cat_lower:
            plain_desc = "Assert Used for Security: The code uses `assert` to enforce a security check. Python removes `assert` statements when running in optimised mode (`-O`), so the check can be silently bypassed."
        else:
            plain_desc = "Python Security Issue: Bandit identified a potentially insecure coding pattern in this Python file."

    return f"**{plain_desc}**\n\nTechnical Details: {original_message}"


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
            "message": get_plain_language_description(
                "Semgrep", 
                result.get("check_id", "Unknown"), 
                extra.get("message", "No description available.")
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
            "message": get_plain_language_description(
                "Gitleaks",
                result.get("RuleID", "Unknown"),
                result.get("Description", "Potential secret detected.")
            )
        })

    return findings


def osv_severity(max_severity, vulnerabilities):
    """Map an OSV group's highest CVSS score onto the project's severity levels."""
    try:
        score = float(max_severity)
    except (TypeError, ValueError):
        score = None

    if score is not None and score > 0:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    # No CVSS score: fall back to the advisory database's own rating where it has one.
    ratings = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for vuln in vulnerabilities:
        rating = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        if rating in ratings:
            return ratings[rating]

    # Unrated vulnerabilities are treated as HIGH so they are not silently passed.
    return "HIGH"


def version_key(version):
    """Sortable key for dotted versions; None when the version is not plainly numeric."""
    parts = str(version).lstrip("vV").split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def osv_fixed_version(package_name, installed_version, vulnerabilities):
    """The lowest fixed version above the installed one that resolves the vulnerability."""
    fixed_versions = set()
    for vuln in vulnerabilities:
        for affected in vuln.get("affected", []):
            if (affected.get("package") or {}).get("name", "").lower() != package_name.lower():
                continue
            for version_range in affected.get("ranges", []):
                # GIT ranges hold commit hashes, not installable versions.
                if version_range.get("type") == "GIT":
                    continue
                for event in version_range.get("events", []):
                    if event.get("fixed"):
                        fixed_versions.add(event["fixed"])

    installed = version_key(installed_version)
    comparable = sorted(
        (version_key(version), version) for version in fixed_versions if version_key(version) is not None
    )
    if installed is not None and comparable:
        newer = [version for key, version in comparable if key > installed]
        return newer[0] if newer else None

    return sorted(fixed_versions)[0] if fixed_versions else None


def osv_title(name, version, vulnerabilities, primary_id):
    """Short card title, e.g. "minimist 1.2.0: Prototype Pollution in minimist"."""
    summary = next((vuln["summary"] for vuln in vulnerabilities if vuln.get("summary")), None)
    if summary is None:
        # Advisories without a summary only have long details, so name the vulnerability by ID.
        return f"{name} {version}: {primary_id}"

    summary = " ".join(summary.split()).rstrip(".")
    if len(summary) > 80:
        summary = summary[:77].rstrip() + "..."
    return f"{name} {version}: {summary}"


def process_osv_scanner():
    data = load_json("osv-scanner.json", {"results": []})
    findings = []

    for result in data.get("results") or []:
        source_path = (result.get("source") or {}).get("path", "Unknown")
        try:
            source_path = str(Path(source_path).resolve().relative_to(ROOT))
        except ValueError:
            pass

        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name = package.get("name", "Unknown Package")
            version = package.get("version", "Unknown Version")
            ecosystem = package.get("ecosystem", "Unknown")
            by_id = {vuln.get("id"): vuln for vuln in entry.get("vulnerabilities") or []}

            # A group is one vulnerability known under several IDs (CVE, GHSA, PYSEC...).
            groups = entry.get("groups") or [{"ids": [vuln_id]} for vuln_id in by_id]
            for group in groups:
                vulns = [by_id[vuln_id] for vuln_id in group.get("ids", []) if vuln_id in by_id]
                if not vulns:
                    continue

                primary_id = group["ids"][0]
                aliases = sorted(set(group.get("aliases") or group.get("ids")) | set(group["ids"]))
                severity = osv_severity(group.get("max_severity"), vulns)
                description = next(
                    (vuln.get(field) for field in ("summary", "details") for vuln in vulns if vuln.get(field)),
                    "Vulnerable dependency detected."
                )
                description = description.strip()
                if description[-1] not in ".!?":
                    description += "."
                fixed = osv_fixed_version(name, version, vulns)
                advice = (
                    f" Fix by upgrading {name} from {version} to {fixed} or later."
                    if fixed else " No fixed version is published yet."
                )

                findings.append({
                    "scanner": "OSV-Scanner",
                    "type": "SCA",
                    "category": primary_id,
                    "title": osv_title(name, version, vulns, primary_id),
                    "severity": severity,
                    "status": get_action(severity),
                    "file": source_path,
                    "line": None,
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "fixed_version": fixed,
                    "aliases": aliases,
                    "message": get_plain_language_description(
                        "OSV-Scanner",
                        primary_id,
                        f"{name} {version} ({ecosystem}): {description}"
                    ) + advice
                })

    return findings


def process_bandit():
    data = load_json("bandit.json", {"results": []})
    findings = []

    for result in data.get("results", []):
        severity = result.get("issue_severity", "LOW").upper()
        test_id = result.get("test_id", "Unknown")
        test_name = result.get("test_name", "Unknown")
        category = f"{test_id}-{test_name}"

        findings.append({
            "scanner": "Bandit",
            "type": "SAST",
            "category": category,
            "severity": severity,
            "status": get_action(severity),
            "file": result.get("filename", "Unknown"),
            "line": result.get("line_number"),
            "message": get_plain_language_description(
                "Bandit",
                category,
                result.get("issue_text", "No description available.")
                + (f" More info: {result['more_info']}" if result.get("more_info") else "")
            )
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
            if (pattern in finding.get("category", "")
                    or pattern in finding.get("file", "")
                    or pattern in finding.get("aliases", [])):
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
    findings.extend(process_osv_scanner())
    findings.extend(process_bandit())
    
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