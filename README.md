# VulnCloud

### Web Security Configuration Assessment Platform

VulnCloud is a Python-based educational web security assessment platform built with Flask. It helps assess common website security configurations by checking HTTP security headers, verifying TLS/SSL certificates, calculating security scores, generating recommendations, maintaining assessment history, and producing PDF reports.

The project is intended for educational use and authorized security configuration assessments.

## Features

### 1. HTTP Security Header Analysis
- Checks important HTTP security headers.
- Identifies present and missing headers.
- Marks checks as not applicable when appropriate.
- Provides security recommendations.

### 2. TLS/SSL Certificate Analysis
- Verifies TLS certificates.
- Reports the negotiated TLS version and certificate issuer.
- Displays certificate expiry information and remaining validity.
- Retains certificate and hostname verification.

### 3. Security Scoring
- Calculates an overall security score.
- Evaluates applicable security checks.
- Provides a security rating.

### 4. Automated Recommendations
- Identifies security configuration weaknesses.
- Explains why findings matter.
- Provides suggested remediation steps.

### 5. Web Dashboard
- Flask-based assessment interface.
- Displays scan results and security scores.
- Supports authorized public website assessments.

### 6. Assessment History
- Stores assessment results using SQLite.
- Displays previous assessments.
- Provides individual assessment details.

### 7. PDF Reporting
- Generates downloadable security assessment reports.
- Includes target information, scores, findings, TLS results, recommendations, and an educational disclaimer.

## Security Controls

VulnCloud includes safeguards designed for authorized assessments:

- Public assessments require explicit authorization confirmation in the dashboard.
- Supports standard HTTP (port 80) and HTTPS (port 443).
- Validates DNS resolution and rejects non-public IP addresses.
- Uses validated, pinned IP addresses for public HTTP/HTTPS connections.
- HTTPS connections retain TLS certificate verification and hostname verification.
- Uses Server Name Indication (SNI) for HTTPS.
- Revalidates redirect destinations before following them.
- Limits redirect handling to three redirects.
- Provides a restricted localhost demonstration target.

These safeguards reduce risks associated with unintended scanning and unsafe network connections. They do not guarantee that every network risk is eliminated.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| Flask | Web dashboard |
| Requests | Local demonstration requests |
| SQLite | Assessment history |
| Certifi | Trusted CA certificates |
| ReportLab | PDF report generation |
| HTML, CSS, JavaScript | Dashboard interface |
| Git and GitHub | Version control |

## Project Structure

```text
VulnCloud/
├── app.py
├── test_site.py
├── requirements.txt
├── scanner/
│   ├── headers.py
│   ├── target_policy.py
│   ├── safe_http.py
│   ├── tls_check.py
│   ├── scoring.py
│   ├── recommendations.py
│   └── history.py
├── reports/
│   ├── __init__.py
│   └── pdf_report.py
├── templates/
│   ├── index.html
│   ├── history.html
│   └── history_detail.html
└── tests/
    ├── test_headers_integration.py
    ├── test_safe_http.py
    ├── test_target_policy.py
    └── test_tls_check.py
```

## Installation

### 1. Clone the repository

```bash
git clone -b main https://github.com/fairoocm/VulnCloud.git
cd VulnCloud
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

### 3. Activate the environment

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

Start the assessment from the dashboard. The local demonstration target does not require public-target authorization.

## Public Website Assessment

To assess a public website:

1. Enter the website URL using HTTP or HTTPS on its standard port.
2. Confirm that you own the target or have explicit permission to assess it.
3. Enable the authorization confirmation checkbox.
4. Start the assessment.
5. Review the security findings, score, TLS information, and recommendations.
6. Generate a PDF report if required.

The dashboard checkbox records the user's authorization confirmation; it does not grant permission. Always obtain permission from the website owner before scanning.

## Running Automated Tests

Run the test suite from the project root:

```powershell
python -m unittest discover -s tests -v
```

The recovery verification run completed with 8 passing tests. This result describes that test run and is not a claim that every possible application behavior has been tested.

## Responsible Use

VulnCloud is intended for educational purposes and authorized security configuration assessments.

Only assess:
- Systems you own.
- Websites for which you have explicit authorization.
- The provided local demonstration target.

Do not use this project to scan unauthorized systems.

A missing security header or a low security score does not automatically indicate an exploitable vulnerability. Findings should be reviewed in the context of the application.

VulnCloud is an educational security configuration assessment tool. It is not a complete penetration-testing framework or a guarantee of security.

## Developer

**Bilal Fairoos**

BCA Student | Cybersecurity Enthusiast

- GitHub: https://github.com/fairoocm
- LinkedIn: https://www.linkedin.com/in/bilal-fairoos-cm-2b5892436

## Project Status

**Phase 11 — Portfolio Preparation**

Core scanner integration and recovery completed.

- HTTP security header analysis
- TLS certificate verification
- Public URL assessment
- Security scoring and recommendations
- Assessment history
- PDF reporting
- Automated recovery tests

Latest verified recovery commit: `e3339ba`
