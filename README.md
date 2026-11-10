
# VulnCloud

### Web Security Configuration Assessment Platform

VulnCloud is a Python-based educational web security assessment tool designed to identify common HTTP security header weaknesses, inspect TLS certificates, calculate security scores, and generate assessment reports through a Flask-based dashboard.

The project focuses on safe, authorized security configuration assessments using explicit target authorization and validated network connections.

## Features

### 1. HTTP Security Header Analysis
- Checks important HTTP security headers.
- Identifies missing and present headers.
- Marks checks as not applicable when appropriate.
- Provides security recommendations.

### 2. TLS/SSL Certificate Analysis
- Inspects TLS certificates.
- Checks certificate verification.
- Reports TLS version and certificate issuer.
- Displays certificate expiry information and remaining validity.

### 3. Security Scoring
- Calculates an overall security score.
- Evaluates applicable security checks.
- Provides a security rating.

### 4. Automated Recommendations
- Identifies security configuration weaknesses.
- Explains why each finding matters.
- Provides suggested remediation steps.

### 5. Web Dashboard
- Flask-based assessment interface.
- Displays scan results and security scores.
- Supports authorized target assessment.

### 6. Assessment History
- Stores assessment results using SQLite.
- Displays previous assessments.
- Provides individual assessment details.

### 7. PDF Reporting
- Generates downloadable security assessment reports.
- Includes target information, scores, findings, TLS results, recommendations, and an educational disclaimer.

## Security Controls

VulnCloud includes safeguards designed for authorized assessment:

- Public scanning requires explicit authorization.
- Public targets must be HTTPS on the standard port 443.
- Public domains must be included in the local authorization list.
- DNS results are checked for non-public IP addresses.
- HTTPS connections use a validated, pinned IP address.
- TLS connections retain hostname verification and SNI.
- Redirect responses are rejected.
- A restricted localhost demo is available for educational testing.

These controls reduce risks associated with unintended scanning and unsafe network connections. They do not make the application a substitute for a professional security testing framework.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Flask | Web dashboard |
| Requests | Local demo HTTP requests |
| SQLite | Assessment history |
| Certifi | Trusted CA certificates |
| ReportLab | PDF report generation |
| HTML, CSS, JavaScript | Dashboard interface |
| Pytest | Automated testing |
| Git and GitHub | Version control |

## Project Structure

```text
VulnCloud/
│
├── app.py
├── test_site.py
├── requirements.txt
│
├── scanner/
│   ├── headers.py
│   ├── target_policy.py
│   ├── safe_http.py
│   ├── tls_check.py
│   ├── scoring.py
│   ├── recommendations.py
│   └── history.py
│
├── reports/
│   ├── __init__.py
│   └── pdf_report.py
│
├── templates/
│   ├── index.html
│   ├── history.html
│   └── history_detail.html
│
└── tests/
    ├── test_headers_integration.py
    ├── test_safe_http.py
    ├── test_target_policy.py
    └── test_tls_check.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/fairoocm/VulnCloud.git
cd VulnCloud
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

## Running VulnCloud

### 1. Start the local demonstration website

Open a terminal and run:

```powershell
python test_site.py
```

Keep this terminal running.

### 2. Start the dashboard

Open a second terminal and run:

```powershell
python app.py
```

### 3. Open the dashboard

Visit:

```text
http://127.0.0.1:8000
```

### 4. Run a local demonstration scan

Enter:

```text
http://localhost:5000
```

Start the assessment from the dashboard.

The local demonstration target does not require public-target authorization.

## Configuring Authorized Public Targets

Public assessments require a local configuration file named:

```text
authorized_targets.json
```

Create this file in the project root with the following structure:

```json
{
    "authorized_targets": [
        "your-authorized-domain.example"
    ]
}
```

Replace the placeholder with a domain you own or have explicit permission to assess.

Important:
- Add domain names, not complete URLs.
- Public targets must use HTTPS on port 443.
- The dashboard authorization checkbox must also be enabled.
- Never add targets without permission.
- Do not commit `authorized_targets.json` to GitHub.

## Running Automated Tests

Install pytest:

```powershell
python -m pip install pytest
```

Run the complete test suite:

```powershell
python -m pytest -q
```

The Phase 10 integration test suite contains 11 tests covering target policy, safe HTTP connections, dashboard integration, and TLS certificate verification.

## Responsible Use

VulnCloud is intended for educational purposes and authorized security configuration assessments.

Only assess:
- Systems you own.
- Websites for which you have explicit authorization.
- The provided local demonstration target.

Do not use this project to scan unauthorized systems.

A missing security header or a low security score does not automatically indicate an exploitable vulnerability. Findings should be reviewed in the context of the application.

VulnCloud is not a complete penetration-testing tool, vulnerability scanner, or guarantee of security.

## Developer

**Bilal Fairoos**

BCA Student | Cybersecurity Enthusiast

- GitHub: https://github.com/fairoocm
- LinkedIn: https://www.linkedin.com/in/bilal-fairoos-cm-2b5892436

## Project Status

**Phase 10 — Scanner Integration: Completed**

- Dashboard and scanner integration
- HTTP security header analysis
- TLS certificate analysis
- Security scoring and recommendations
- Assessment history
- PDF reporting
- Automated tests

**Phase 11 — Portfolio Documentation: In Progress**
