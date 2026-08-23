# Runs the SAST and secret scan
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
        "detect",
        ".",
        "--report-format", "json",
        "--report-path", "results/gitleaks.json",
        "--redact"
    ])

    print(f"Gitleaks finished with exit code {result.returncode}")

    if result.stderr:
        print(result.stderr)

    return result.returncode


def run_pip_audit():
    print("Running pip-audit...")

    result = run_command([
        "pip-audit",
        "-r", "test_cases/vulnerable_requirements.txt",
        "-f", "json",
        "-o", "results/pip-audit.json"
    ])

    print(f"pip-audit finished with exit code {result.returncode}")

    if result.stderr:
        print(result.stderr)

    return result.returncode


if __name__ == "__main__":

    print("=" * 50)
    print("SECURITY SCAN")
    print("=" * 50)

    run_semgrep()
    run_gitleaks()
    run_pip_audit()

    print("\nRaw scan results saved to results/")