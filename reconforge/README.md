# ReconForge

**Universal OSINT & Static Analysis Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: Windows/Linux/Docker](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Docker-blue.svg)]()
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()

ReconForge is a one-click OSINT and static analysis tool that accepts any target type — URL, IP address, APK, thick client application, or Active Directory domain — and performs exhaustive reconnaissance across 60+ modules. Results are validated to eliminate false positives, cross-correlated to discover attack chains, and delivered through an interactive web UI with exportable reports in 7 formats.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Windows (Recommended)](#windows-recommended)
  - [Linux / WSL](#linux--wsl)
  - [Docker](#docker)
- [Quick Start](#quick-start)
- [Step-by-Step Usage Guide](#step-by-step-usage-guide)
- [Target Types](#target-types)
  - [URL / Web Application](#1-url--web-application-28-modules)
  - [IP Address](#2-ip-address-14-modules)
  - [Active Directory](#3-active-directory-8-modules)
  - [APK / Android App](#4-apk--android-app-15-modules)
  - [Thick Client (EXE/JAR/.NET)](#5-thick-client-exejarnet-13-modules)
- [Validation Engine](#validation-engine)
- [Cross-Correlation Engine](#cross-correlation-engine)
- [Report Formats](#report-formats)
- [API Keys Configuration](#api-keys-configuration)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **5 target types** — URL, IP, APK, thick client, Active Directory
- **60+ OSINT/analysis modules** — DNS, WHOIS, subdomains, SSL, headers, ports, SMB, LDAP, Kerberos, APK decompile, .NET/.JAR decompile, secret scanning, crypto audit, SDK detection, CVE lookup, and more
- **False positive validation** — multi-strategy engine re-verifies findings before reporting
- **Cross-correlation** — links findings from different modules into attack chains (e.g., leaked API key + accessible endpoint = critical)
- **Web UI** — dark-themed React dashboard with real-time scan progress, interactive findings, asset graph
- **7 report formats** — HTML, PDF, JSON, Markdown, CSV, DOCX, SARIF
- **API keys optional** — all core modules work without paid APIs; keys enhance coverage
- **One-click scan** — select target type, paste/upload, click Start
- **Docker support** — single `docker compose up` deploys everything

---

## Requirements

| Requirement | Minimum |
|---|---|
| OS | Windows 10+, Linux (Ubuntu 20.04+), or Docker |
| Python | 3.10 or higher |
| Node.js | 18+ (for frontend build; optional) |
| RAM | 4 GB minimum, 8 GB recommended |
| Disk | 2 GB for tool + space for scan data |

### Optional External Tools (enhance functionality)

| Tool | Purpose | Install |
|---|---|---|
| nmap | Port scanning + service detection | [nmap.org](https://nmap.org/download.html) |
| jadx | APK decompilation | Auto-installed by setup.bat |
| apktool | APK resource decoding | Auto-installed by setup.bat |
| smbclient | SMB enumeration | `apt install smbclient` or Nmap scripts |
| Java JRE | Required for jadx/apktool | [java.com](https://java.com) |

---

## Installation

### Windows (Recommended)

```batch
:: 1. Clone or download the project
cd C:\path\to\reconforge

:: 2. Run the setup script (as Administrator recommended)
setup.bat

:: 3. Configure API keys (optional but recommended)
:: Edit .env file with your API keys

:: 4. Start the server
start.bat

:: 5. Open browser
:: Navigate to http://localhost:8800
```

**What setup.bat does:**
1. Checks Python 3.10+, Node.js, Git
2. Creates virtual environment and installs Python packages
3. Downloads jadx, apktool, nuclei, subfinder
4. Builds the React frontend
5. Creates data directories
6. Initializes the SQLite database
7. Creates .env configuration file

### Linux / WSL

```bash
# 1. Clone the project
cd /path/to/reconforge

# 2. Install system dependencies
sudo apt update && sudo apt install -y python3-venv python3-pip \
  nmap whois dnsutils smbclient default-jre-headless curl unzip

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Build frontend (if Node.js available)
cd frontend && npm install && npx vite build && cd ..

# 6. Configure API keys
cp .env.example .env
nano .env  # Add your API keys

# 7. Initialize database
python -c "from backend.database import init_db; init_db()"

# 8. Start the server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8800 --reload
```

### Docker

```bash
# 1. Build and start
docker compose up -d

# 2. Open browser
# Navigate to http://localhost:8800

# With API keys:
# Edit .env before building, or pass as environment variables:
docker compose up -d -e RF_SHODAN_API_KEY=your_key_here
```

---

## Quick Start

```
1. Run setup.bat (one time)
2. Run start.bat
3. Open http://localhost:8800
4. Click "New Scan"
5. Select target type (URL / IP / APK / Thick Client / AD)
6. Paste URL/IP or upload file
7. Click "Start Scan"
8. Watch real-time progress
9. Review findings (validated, no false positives)
10. Download report (HTML / PDF / JSON / MD / CSV)
```

---

## Step-by-Step Usage Guide

### Step 1: Start the Application

```batch
:: Windows
start.bat

:: Linux
source venv/bin/activate
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8800
```

Open `http://localhost:8800` in your browser.

### Step 2: Create a New Scan

1. Click **"New Scan"** in the sidebar
2. Choose your **target type**:
   - **URL** — paste the full URL (e.g., `https://example.com`)
   - **IP** — enter the IP address (e.g., `192.168.1.1`)
   - **APK** — click "Upload" and select the .apk file
   - **Thick Client** — click "Upload" and select the .exe / .jar / .dll file
   - **Active Directory** — enter the domain controller IP or domain name

3. **Module Selection** (optional):
   - All modules for the target type are enabled by default
   - Uncheck modules you don't need to speed up the scan
   - Modules requiring API keys show a status indicator (green = configured)

4. Click **"Start Scan"**

### Step 3: Monitor Progress

- The **Scan Detail** page shows real-time progress via WebSocket
- See which module is currently running
- Watch findings count increase as modules complete
- Module timeline shows completed (green), running (blue), pending (gray)

### Step 4: Review Findings

When the scan completes:

1. **Findings Tab** — all findings sorted by severity
   - Each finding shows: severity badge, title, module name, confidence score
   - Click to expand for full details: description, evidence, impact, remediation
   - Validation status: Confirmed (green), False Positive (red), Uncertain (yellow)
   - Manually override validation: click Confirm or Reject

2. **Assets Tab** — everything discovered
   - Grouped by type: domains, IPs, endpoints, emails, secrets, technologies, etc.
   - Search and filter
   - Click any asset for metadata and source module

3. **Correlations Tab** — attack chains
   - Shows how findings link together (e.g., exposed secret + accessible API = critical chain)
   - Combined CVSS score for the chain

4. **Modules Tab** — execution details
   - Duration per module, findings per module, errors

### Step 5: Generate Report

1. Go to **Reports** page
2. Select the scan
3. Choose format:
   - **HTML** — interactive, best for analysis (open in browser)
   - **PDF** — professional, for client delivery
   - **JSON** — machine-readable, for tool integration
   - **Markdown** — for GitHub, wikis, issue trackers
   - **CSV** — for spreadsheet analysis
4. Click **"Generate & Download"**

### Step 6: Configure API Keys (Enhance Results)

Go to **Settings** page or edit `.env`:

| Key | Free Tier | What it enables |
|---|---|---|
| Shodan | 100 queries/month | IP service lookup, CVE mapping, banner analysis |
| VirusTotal | 500 lookups/day | Threat intel, subdomain enum, malware check |
| SecurityTrails | 50 queries/month | DNS history, extensive subdomain enum |
| Hunter.io | 25 searches/month | Email harvesting by domain |
| GitHub Token | 5000 requests/hour | Code search for leaked secrets |
| AbuseIPDB | 1000 checks/day | IP reputation and blocklist checking |

**Without any API keys**, ReconForge still runs 40+ modules using:
- Direct DNS queries (dnspython)
- crt.sh (free Certificate Transparency)
- WHOIS lookups (free)
- HTTP/HTTPS probing
- nmap port scanning
- File-based analysis (APK/thick client)
- AlienVault OTX (free)
- HackerTarget (free)

---

## Target Types

### 1. URL / Web Application (28 modules)

**What it does:** Complete web application reconnaissance and security analysis.

| Category | Modules |
|---|---|
| DNS Intelligence | DNS Records, DNS History, Zone Transfer |
| Domain Intelligence | WHOIS, Subdomain Enumeration, Live Host Check |
| SSL/TLS | Certificate Analysis, Security Headers, CORS Policy |
| Content Discovery | Robots.txt/Sitemap, Wayback Machine, JS Analysis, Google Dorking |
| Technology | Tech Fingerprint, WAF Detection, Favicon Hash |
| People & Email | Email Harvest, SPF/DMARC/DKIM, Social Links, Breach Search |
| Cloud & Code | Cloud Storage Enum, GitHub Dorking, Metadata Extraction |

**Example findings:**
- Missing Content-Security-Policy header (MEDIUM)
- SPF record with ~all allows spoofing (MEDIUM)
- AWS API key found in JavaScript bundle (CRITICAL)
- Exposed .git directory (HIGH)
- Subdomain pointing to unclaimed S3 bucket (HIGH)

### 2. IP Address (14 modules)

**What it does:** Network reconnaissance, service discovery, and vulnerability mapping.

| Category | Modules |
|---|---|
| Network Intel | IP WHOIS, Geolocation, ASN Info, Shodan Lookup, Reverse DNS, Threat Intel |
| Port & Service | Port Scan, Banner Grab, Service Enumeration, SSL Cert Scan |
| Protocol Enum | SMB, SNMP, SMTP, RPC |

**Example findings:**
- MySQL accessible without authentication on port 3306 (CRITICAL)
- SMB null session allows user enumeration (HIGH)
- SMTP server allows open relay (HIGH)
- Known CVE-2024-XXXX in Apache 2.4.49 (CRITICAL)

### 3. Active Directory (8 modules)

**What it does:** AD-specific reconnaissance for internal penetration testing.

| Category | Modules |
|---|---|
| Domain Recon | AD DNS Records, LDAP Enumeration, Null Session, Domain Trusts |
| Auth Recon | Kerberos User Enum, AS-REP Roasting, Password Policy, ADCS Check |

**Example findings:**
- LDAP allows anonymous binding (HIGH)
- 3 accounts vulnerable to AS-REP Roasting (HIGH)
- ADCS template ESC1 misconfigured (CRITICAL)
- Password policy requires only 6 characters, no lockout (MEDIUM)

### 4. APK / Android App (15 modules)

**What it does:** Complete mobile application analysis — store OSINT + static code review.

| Category | Modules |
|---|---|
| Store Intel | Play Store Metadata, Developer OSINT |
| Manifest | Manifest Analysis, Permission Risk, Component Map, Deeplink Map |
| Code | Secret Scanning, Endpoint Extraction, Crypto Audit, Storage Patterns, WebView Audit |
| SDK/Framework | Framework Detection, SDK Map, Tracker Detection, Native Lib Analysis |

**Example findings:**
- AWS access key AKIA... found in BuildConfig.java (CRITICAL)
- Application is debuggable (android:debuggable="true") (HIGH)
- Firebase database at project-id.firebaseio.com is publicly readable (CRITICAL)
- 12 trackers detected including Facebook SDK, Google Analytics, Adjust (INFO)
- WebView with addJavascriptInterface and file access enabled (HIGH)

### 5. Thick Client (EXE/JAR/.NET) (13 modules)

**What it does:** Desktop application reverse engineering and security analysis.

| Category | Modules |
|---|---|
| Binary | Metadata, Strings Extraction, Code Signing, Packing Detection |
| Code | Decompilation, Secret Scanning, Endpoint Extraction, Config Files |
| Security | Dependency CVEs, Unsafe API Usage, Crypto Audit, Privilege Analysis, Update Mechanism |

**Example findings:**
- SQL connection string with credentials in app.config (CRITICAL)
- Update mechanism uses HTTP without certificate validation (HIGH)
- Known CVE in bundled Newtonsoft.Json 12.0.1 (MEDIUM)
- Application uses DESCryptoServiceProvider (weak encryption) (HIGH)
- Binary is not code-signed (MEDIUM)

---

## Validation Engine

ReconForge validates every finding before reporting to eliminate false positives:

| Strategy | What it does |
|---|---|
| **Re-verification** | Critical/High findings are independently re-tested (e.g., re-check if port is actually open, re-fetch header) |
| **Confidence scoring** | Each finding has a confidence score (0-1). Below 0.3 = rejected |
| **Known FP patterns** | Matches against database of known false positives (example/test values, placeholder emails, localhost) |
| **Context validation** | Verifies finding makes sense for the target (e.g., subdomain finding must relate to the target domain) |
| **Evidence quality** | Findings without adequate evidence are downgraded or rejected |
| **Secret entropy** | Detected secrets are checked for entropy — low entropy = likely placeholder |

**Result:** Only confirmed findings appear in the report. False positives are flagged but hidden by default.

---

## Cross-Correlation Engine

After all modules complete, the correlation engine links findings together:

| Chain Type | Example |
|---|---|
| Secret + Endpoint | AWS key found in JS + accessible S3 API endpoint = confirmed data access |
| Subdomain Takeover | NXDOMAIN subdomain + cloud service CNAME = domain takeover |
| Debug + Public | debuggable=true + publicly accessible endpoint = stack trace exposure |
| Weak Crypto + Secret | DES encryption + stored credentials = recoverable credentials |
| SPF + Email | Misconfigured SPF + harvested employee emails = phishing vector |
| Service + CVE | Outdated Apache + known CVE = exploitable vulnerability |
| WebView + File | JavaScript interface + file access = local file exfiltration |

Each correlation gets a combined CVSS score reflecting the chain's impact.

---

## Saved Results (Auto-Save)

Every completed scan automatically saves its results to `data/results/{scan_id}/`:

```
data/results/1/
├── scan_info.json           # Scan metadata (target, risk score, dates)
├── findings.json            # All confirmed findings with evidence
├── false_positives.json     # Rejected findings (for manual review)
├── assets.json              # All discovered assets grouped by type
├── correlations.json        # Attack chain correlations
├── modules.json             # Module execution details + raw output
└── summary.md               # Human-readable summary
```

**From the Web UI (Results page):**
- Browse all saved result folders
- Preview any JSON/MD file inline
- Download individual files or entire folder as ZIP
- Delete results you no longer need

**From the API:**
- `GET /api/results` — list all saved result folders
- `GET /api/results/{id}/{filename}` — download a specific file
- `GET /api/results/{id}/download/zip` — download everything as ZIP
- `DELETE /api/results/{id}` — delete entire result folder

Results persist on disk even if you clear the database. They are human-readable JSON and Markdown — open directly in any editor.

---

## Report Formats

| Format | Extension | Use Case |
|---|---|---|
| HTML | .html | Interactive report with expandable sections, search, charts |
| PDF | .pdf | Professional client deliverable with table of contents |
| JSON | .json | Machine-readable for tool integration, CI/CD pipelines |
| Markdown | .md | GitHub issues, wiki pages, documentation |
| CSV | .csv | Spreadsheet analysis, bulk processing |
| DOCX | .docx | Editable Word document for corporate reports |
| SARIF | .sarif | IDE integration (VS Code, GitHub Code Scanning) |

**Report sections:**
1. Executive Summary — risk score, finding counts, key risks
2. Target Profile — technology stack, infrastructure, personnel
3. Attack Surface Map — all discovered assets and relationships
4. Findings — organized by severity, with full evidence
5. Attack Chains — correlated findings with combined impact
6. OSINT Intelligence — domain, network, personnel, code, breach, threat intel
7. Module Execution — what ran, duration, coverage
8. Methodology — tools used, scan parameters

---

## API Keys Configuration

Edit `.env` or configure through the Settings page in the web UI:

```env
# Shodan — https://account.shodan.io/
RF_SHODAN_API_KEY=your_key_here

# VirusTotal — https://virustotal.com/gui/my-apikey
RF_VIRUSTOTAL_API_KEY=your_key_here

# SecurityTrails — https://securitytrails.com/app/account
RF_SECURITYTRAILS_API_KEY=your_key_here

# Hunter.io — https://hunter.io/api-keys
RF_HUNTER_API_KEY=your_key_here

# GitHub — https://github.com/settings/tokens
RF_GITHUB_TOKEN=your_token_here

# AbuseIPDB — https://www.abuseipdb.com/account/api
RF_ABUSEIPDB_API_KEY=your_key_here
```

Restart the server after changing .env values.

---

## API Documentation

Once running, visit `http://localhost:8800/docs` for the interactive Swagger UI.

Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/scans | Create new scan |
| GET | /api/scans | List all scans |
| GET | /api/scans/{id} | Scan details with findings |
| POST | /api/scans/{id}/start | Start a scan |
| POST | /api/scans/{id}/cancel | Cancel running scan |
| GET | /api/findings | List findings (filterable) |
| PATCH | /api/findings/{id}/validate | Manually validate/reject |
| POST | /api/reports/generate | Generate downloadable report |
| GET | /api/results | List all saved result folders |
| GET | /api/results/{id} | List files in a result folder |
| GET | /api/results/{id}/{file} | Download/view a result file |
| GET | /api/results/{id}/download/zip | Download all results as ZIP |
| DELETE | /api/results/{id} | Delete a result folder |
| DELETE | /api/results/{id}/{file} | Delete a single result file |
| GET | /api/dashboard | Dashboard statistics |
| GET | /api/modules | List available modules |
| WS | /ws/scan/{id} | Real-time scan progress |

---

## Architecture

```
reconforge/
├── backend/
│   ├── main.py                    # FastAPI application
│   ├── config.py                  # Settings (env-driven)
│   ├── database.py                # SQLAlchemy engine
│   ├── models.py                  # ORM models
│   ├── schemas.py                 # Pydantic schemas
│   ├── core/
│   │   ├── scanner.py             # Scan orchestrator
│   │   ├── validator.py           # False positive validator
│   │   └── correlator.py          # Cross-correlation engine
│   ├── modules/
│   │   ├── base.py                # BaseModule interface
│   │   ├── web/                   # 28 web recon modules
│   │   ├── ip/                    # 14 IP recon modules
│   │   ├── ad/                    # 8 AD recon modules
│   │   ├── apk/                   # 15 APK analysis modules
│   │   └── thick/                 # 13 thick client modules
│   ├── api/
│   │   ├── scans.py               # Scan CRUD + execution
│   │   ├── findings.py            # Finding management
│   │   ├── reports.py             # Report generation
│   │   ├── dashboard.py           # Dashboard stats
│   │   └── ws.py                  # WebSocket progress
│   └── templates/
│       └── report.html            # HTML report template
├── frontend/
│   └── src/
│       ├── pages/                 # Dashboard, NewScan, ScanDetail, etc.
│       └── components/            # RiskMeter, FindingCard, ScanProgress, etc.
├── setup.bat                      # Windows installer
├── start.bat                      # Launch server
├── Dockerfile                     # Container build
├── docker-compose.yml             # One-command deploy
├── requirements.txt               # Python dependencies
├── .env.example                   # Configuration template
└── README.md                      # This file
```

---

## Troubleshooting

### "Module X failed" or "Command not found"

Some modules require external tools (nmap, jadx, smbclient). Install them:
```batch
:: Windows — run setup.bat which auto-installs most tools
setup.bat

:: Linux
sudo apt install nmap smbclient whois dnsutils default-jre-headless
```

### Port 8800 already in use

```batch
:: Windows
netstat -ano | findstr :8800
taskkill /PID <pid> /F

:: Linux
lsof -i :8800
kill -9 <pid>
```

### API key not working

- Check .env format: `RF_SHODAN_API_KEY=your_key` (no quotes, no spaces)
- Restart the server after editing .env
- Check Settings page for key status indicators

### Large APK upload fails

Increase upload size: set `RF_MAX_UPLOAD_SIZE_MB=1000` in .env

### Scan takes too long

- Reduce modules: deselect unnecessary modules before starting
- Reduce port scan scope: set `RF_MAX_PORTS=100` in .env
- Increase concurrency: set `RF_MAX_CONCURRENT_MODULES=12` in .env

### Database locked (SQLite)

Switch to PostgreSQL for concurrent access:
```env
RF_DB_URL=postgresql://user:pass@localhost/reconforge
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Write your module extending `BaseModule` in the appropriate directory
4. Add it to `backend/modules/__init__.py` registry
5. Test with a real target
6. Submit a pull request

### Writing a New Module

```python
from backend.modules.base import (
    BaseModule, ModuleResult, ModuleFinding, ModuleAsset,
    FindingSeverity, AssetType,
)

class MyModule(BaseModule):
    name = "my_module"
    display_name = "My Module"
    description = "What this module does"
    target_types = ["url"]  # url, ip, apk, thick_client, active_directory
    category = "recon"

    async def run(self, target, scan_context, progress_callback):
        result = ModuleResult()
        # ... your logic here ...
        result.findings.append(ModuleFinding(
            title="Found something",
            description="Detailed description",
            severity=FindingSeverity.HIGH,
            category="misconfiguration",
            evidence="Raw evidence here",
            impact="What an attacker can do",
            remediation="How to fix it",
            confidence=0.9,
        ))
        return result
```

---

## License

[MIT](LICENSE)
