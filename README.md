

\# VulnCloud 



\### Cloud \& Web Security Assessment Platform



VulnCloud is a Python-based security assessment project designed to help identify basic web security configuration issues and analyze cloud security configurations.



\##  Project Objectives



\- Automate basic web security checks.

\- Identify missing HTTP security headers.

\- Analyze SSL/TLS configurations.

\- Assess cloud configuration security.

\- Generate structured security reports.



\## 🛠️ Technology Stack



\- Python

\- Flask

\- Requests

\- dnspython

\- SQLite

\- HTML, CSS and JavaScript

\- Git and GitHub



\##  Current Features



\### HTTP Security Header Analyzer



\- Sends HTTP requests to an authorized target.

\- Checks important HTTP security headers.

\- Identifies missing security headers.

\- Provides basic security recommendations.

\- Handles connection errors.



\## 🚧 Planned Features



\- SSL/TLS certificate analysis.

\- Security scoring system.

\- Web-based dashboard.

\- Cloud configuration assessment.

\- PDF report generation.

\- Assessment history.



\## 💻 Installation



Clone the repository:



```bash

git clone https://github.com/fairoocm/VulnCloud.git

cd VulnCloud

```



Create a virtual environment:



```bash

python -m venv venv

```



Activate on Windows:



```powershell

.\\venv\\Scripts\\Activate.ps1

```



Install dependencies:



```bash

pip install -r requirements.txt

```



\## ▶️ Usage



Run the HTTP security analyzer:



```bash

python scanner/headers.py

```



Enter an authorized HTTPS website when prompted.



\## 🔒 Responsible Use



Use VulnCloud only on systems you own or have explicit permission to assess.



This project is intended for educational and authorized security testing.



Missing security headers do not automatically indicate exploitable vulnerabilities.



\## 👨‍💻 Developer



Bilal Fairoos



GitHub: https://github.com/fairoocm



LinkedIn: https://www.linkedin.com/in/bilal-fairoos-cm-2b5892436



\## 📌 Project Status



Currently under active development.



