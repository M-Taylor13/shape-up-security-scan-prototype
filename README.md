# Security Scanner Prototype

Prototype for automated security analysis of application repositories as part of the Capstone project.

The prototype currently investigates:

* **SAST** using Semgrep
* **Secret detection** using Gitleaks
* Automated security scanning through **GitHub Actions**
* Processing scanner results into a common format
* A basic dashboard for displaying security findings

## Project Structure

```text
security-scanner-prototype/
│
├── .github/
│   └── workflows/
│       └── security-scan.yml       # GitHub Actions security workflow
│
├── scanner/
│   ├── scan.py               # Runs security scanners locally
│   ├── process_results.py    # Processes scanner results
│   └── criteria.py           # Security severity/pass-fail criteria
│
├── dashboard/
│   └── app.py                # Basic Streamlit dashboard
│
├── test_cases/
│   ├── secure_code.py        # Expected to pass
│   ├── sql_injectable.py     # Deliberately vulnerable test
│   ├── xss_vulnerable.py     # Deliberately vulnerable test
│   └── fake_API_key.py       # Fake credential for secret scanning
│
├── results/                  # Local scanner output
├── requirements.txt
└── README.md
```

## Tools

### Semgrep

Semgrep is used for Static Application Security Testing (SAST).

The prototype uses Semgrep to identify potentially vulnerable code patterns such as:

* SQL injection
* Cross-site scripting
* Command injection
* Other insecure coding patterns

### Gitleaks

Gitleaks is used to identify potential secrets and credentials exposed within the repository.

Test credentials must always be fake/non-functional.

## Running Locally

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

Run the scanners:

```bash
python scanner/scan.py
```

Process the results:

```bash
python scanner/process_results.py
```

Run the dashboard:

```bash
streamlit run dashboard/app.py
```

## GitHub Actions

The repository contains a GitHub Actions workflow at:

```text
.github/workflows/security-scan.yml
```

The workflow automatically runs when code is pushed to the repository or when a pull request is created.

The workflow currently runs:

1. Semgrep
2. Gitleaks

The purpose of the workflow is to demonstrate automated security analysis as part of a CI/CD pipeline.

## Test Cases

The `test_cases/` directory contains deliberately vulnerable code used to verify that the scanners behave as expected.

These files are **test fixtures only** and must never contain real credentials.

Expected behaviour:

| Test                | Expected result  |
| ------------------- | ---------------- |
| `secure_code.py`    | Pass             |
| `sql_injectable.py` | Security finding |
| `xss_vulnerable.py` | Security finding |
| `fake_API_key.py`   | Secret finding   |

## Current Limitations

This is an early prototype.

The current implementation does not attempt to detect every type of vulnerability. In particular, vulnerabilities that depend heavily on application context, such as some forms of IDOR or business-logic flaws, may not be reliably detected through static analysis alone.

Security severity thresholds and pipeline failure criteria are currently subject to the project's security analysis criteria.

## Future Work

Potential future improvements include:

* Improved severity classification
* Human-readable remediation recommendations
* Dependency scanning
* Infrastructure-as-Code scanning
* Container scanning
* Improved dashboard
* Integration with the project's main CI/CD platform
* Automated remediation suggestions
