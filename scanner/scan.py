# Runs the SAST and secret scan
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

RESULTS.mkdir(exist_ok=True)


def run_command(command):
    """Run a command and return its output."""

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True
    )

    return result


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


if __name__ == "__main__":

    print("=" * 50)
    print("SECURITY SCAN")
    print("=" * 50)

    run_semgrep()
    run_gitleaks()

    print("\nRaw scan results saved to results/")