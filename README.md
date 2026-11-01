# OWASP ZAP — Vulnerability Detection in Web Applications

A complete automated web application security testing system built using OWASP ZAP, MongoDB, Flask, and Python as part of a Cybersecurity Internship at skillogic, Chennai.

## Project Overview
- **Target:** DVWA (Damn Vulnerable Web Application)
- **Scanner:** OWASP ZAP 2.17.0 in daemon mode
- **Total Alerts Collected:** 841 across 6 scan types


## Tech Stack
- OWASP ZAP 2.17.0
- Python 3.13 + Flask 3.1.3
- MongoDB + PyMongo
- Bootstrap 5 + Chart.js
- Kali Linux 2026.1

## Features
- Automated passive and active scanning via ZAP Python API
- Targeted scans: SQL Injection, XSS, Command Injection, LFI/RFI
- Login page fuzzing with 20 payload types
- MongoDB storage with 6 scan type categories
- Flask dashboard with charts, filters, pagination, alert detail view
- REST API endpoints for risk summary and alerts
- Consolidated HTML vulnerability report generation

## Setup Instructions
```bash
# 1. Install dependencies
sudo apt install apache2 mariadb-server php zaproxy mongodb

# 2. Clone and setup
git clone <repo-url>
cd zap_project
python3 -m venv venv
source venv/bin/activate
pip install flask pymongo python-owasp-zap-v2.4 requests python-dotenv

# 3. Create .env file
cp .env.example .env
# Edit .env with your settings

# 4. Start ZAP daemon
zaproxy -daemon -port 8080 -config api.key=zapkey123 -config insights.enabled=false -Xmx1024m &

# 5. Run Flask dashboard
python3 app.py
```

## Dashboard Pages
| Page | URL | Description |
|------|-----|-------------|
| Dashboard | / | Stat cards, risk charts, scan history |
| Alerts | /alerts | 841 alerts with filters and pagination |
| Summary | /summary | Per-scan-type vulnerability cards |
| Scans | /scans | Scan history |
| API | /api/risk-summary | JSON risk summary |

## Intern
**Padmanathan** | MCA | Rajiv Gandhi College of Engineering and Technology  
Cybersecurity Intern — skillogic, Chennai  
padmanathan948@gmail.com
