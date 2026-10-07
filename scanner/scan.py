# Runs the SAST, secret, SCA, and Python-specific SAST scans
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

RESULTS.mkdir(exist_ok=True)


def run_command(command):
    """Run a command and return its output."""

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True
        )
        return result
    except FileNotFoundError:
        class MockResult:
            returncode = 127
            stderr = f"Error: '{command[0]}' not found. Is it installed?"
        return MockResult()


def run_semgrep():
    print("Running Semgrep...")

    result = run_command([
        "semgrep",
        "--config", "auto",
        "--json",
        "--output", "results/semgrep.json",
        "."
    ])

    print(f"Semgrep finished with exit code {result.returncode}")

    if result.stderr:
        print(result.stderr)

    return result.returncode


def run_gitleaks():
    print("Running Gitleaks...")

    result = run_command([
        "gitleaks",
        "dir",
        ".",
        "--report-format", "json",
        "--report-path", "results/gitleaks.json",
        "--redact"
    ])

    print(f"Gitleaks finished with exit code {result.returncode}")

    if result.stderr:
        print(result.stderr)

    return result.returncode


# Extra dependency files whose names OSV-Scanner would not recognise on its own.
# Format: "<parser>:<path>", see the OSV-Scanner --lockfile option.
EXTRA_LOCKFILES = [
    "requirements.txt:test_cases/vulnerable_requirements.txt",
]


def run_osv_scanner():
    """Software composition analysis for every supported ecosystem in the repository.

    OSV-Scanner finds lockfiles and manifests recursively (npm, PyPI, Go, Maven,
    Cargo, NuGet and more) and checks each dependency against the OSV database.
    """
    print("Running OSV-Scanner...")

    command = [
        "osv-scanner",
        "scan", "source",
        "--recursive",
        "--format", "json",
        "--output-file", "results/osv-scanner.json",
    ]
    for lockfile in EXTRA_LOCKFILES:
        command += ["--lockfile", lockfile]
    command.append(".")

    result = run_command(command)

    # Exit code 1 means vulnerabilities were found, 128 means no dependency files were found.
    print(f"OSV-Scanner finished with exit code {result.returncode}")

    if result.returncode not in (0, 1) and result.stderr:
        print(result.stderr)

    return result.returncode


def run_bandit():
    print("Running Bandit...")

    result = run_command([
        "bandit",
        "-r", ".",
        "-f", "json",
        "-o", "results/bandit.json",
        "--exclude", ".git,results,.venv,venv,node_modules"
    ])

    # Bandit exits with code 1 when it finds issues (not a true error)
    if result.returncode not in (0, 1):
        print(f"Bandit finished with exit code {result.returncode}")
    else:
        print(f"Bandit finished with exit code {result.returncode}")

    if result.stderr:
        print(result.stderr)

    return result.returncode


if __name__ == "__main__":

    print("=" * 50)
    print("SECURITY SCAN")
    print("=" * 50)

    run_semgrep()
    run_gitleaks()
    run_osv_scanner()
    run_bandit()

    print("\nRaw scan results saved to results/")