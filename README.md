<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Never_Dead_End-Engine-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Modules-16-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tests-58_Passed-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge"/>
</p>

<h1 align="center">⚡ AmonStrike</h1>
<p align="center"><b>Hidden Reconnaissance. Precise Strike. Never Dead-End.</b></p>
<p align="center">Advanced Bug Bounty Reconnaissance Framework — Named after Amon, the Egyptian god of the hidden</p>

---

## Philosophy

> A real target is NEVER clean. There is ALWAYS something.
> When one door closes — try the window, the roof, the basement.
> When nothing is found — dig deeper, try a different angle.
> Never return empty-handed.

AmonStrike is built around the **Never Dead-End Engine** — a scan graph where every finding is a node that triggers the next attack action, and every dead-end has 15 automatic fallback strategies.

---

## Quick Start

```bash
git clone https://github.com/JarDaNi686/AmonStrike.git
cd AmonStrike
sudo python3 amonstrike.py
```

The launcher will:
1. Auto-install any missing tools (21 tools, multiple install methods)
2. Start the real-time split-terminal UI
3. Run the Never Dead-End engine in background
4. Execute all 16 scan modules
5. Generate HTML + PDF report

---

## Scan Modes

```bash
# Fast — essential checks (~5 min)
sudo python3 amonstrike.py --url http://target.com --mode fast

# Normal — all modules (~15 min) [default]
sudo python3 amonstrike.py --url http://target.com

# Deep — all modules + NDE + tool chaining (~45 min)
sudo python3 amonstrike.py --url http://target.com --mode deep

# NDE — full autonomous recon
sudo python3 amonstrike.py --url http://target.com --mode nde

# Specific modules
sudo python3 amonstrike.py --url http://target.com --modules sqli,xss,cors

# No UI (standard output)
sudo python3 amonstrike.py --url http://target.com --no-ui
```

---

## Real-Time Console UI

```
╔══════════════════════════════════════════════════════════════╗
║ ⚡ AMONSTRIKE │ http://target.com │ Module 3/16: sqli        ║
║                    CRIT:2 HIGH:5 MED:3 │ Nodes:47 Finds:10  ║
╠═══════════════════════════╦══════════════════════════════════╣
║ ⟫ SCAN PROGRESS           ║ ⟫ FINDINGS                       ║
║ 09:15:22 [+] [sqli]       ║ [CRIT] sqli   SQL Injection...  ║
║   SQL Injection found!    ║ [HIGH] xss    Reflected XSS...  ║
║ 09:15:23 [i] [sqli]       ║ [HIGH] auth   No rate limiting  ║
║   Parameter: id           ║ [MED]  cors   CORS wildcard...  ║
║ 09:15:24 [*] [sqli]       ║ [LOW]  recon  Server version... ║
║   Testing forms...        ║                                  ║
╠═══════════════════════════╩══════════════════════════════════╣
║ ⟫ ATTACK GRAPH                                               ║
║ [TARGET: http://target.com]    ▶ Running: sqlmap             ║
║   ├─ web_service    ████ (4)   ◉ Phase: Module 3/16         ║
║   ├─ directory      ██ (12)    ↺ Dead-ends escaped: 2        ║
║   ├─ form           █ (3)      ⚙ Tools: nmap,ffuf,sqlmap    ║
║   ├─ vulnerability  █ (7)                               ⠋   ║
╚══════════════════════════════════════════════════════════════╝
 [q]Quit  [↑↓]Scroll Log  [PgUp/PgDn]Findings  [s]Save
```

---

## Never Dead-End Engine

### Node Types (25)
```
DOMAIN · SUBDOMAIN · IP_ADDRESS · OPEN_PORT · WEB_SERVICE
LOGIN_PAGE · API_ENDPOINT · ADMIN_PANEL · JS_FILE · FORM
PARAMETER · COOKIE · EMAIL · CREDENTIAL · VULNERABILITY
TECHNOLOGY · ERROR_PAGE · FILE_UPLOAD · REDIRECT · DIRECTORY
DATABASE_ERROR · WAF_DETECTED · CMS_DETECTED · JWT_TOKEN · API_KEY
```

### Action Chain
```
DOMAIN        → subdomain enumeration + nmap scan
OPEN_PORT     → web service detection
WEB_SERVICE   → whatweb + form extraction + ffuf dirs + nuclei
FORM          → sqlmap SQLi testing
PARAMETER     → SQLi + XSS + LFI + SSRF testing
JS_FILE       → endpoint extraction + secret finding
CMS_DETECTED  → CMS-specific scanner (wpscan/droopescan)
WAF_DETECTED  → WAF bypass techniques
CREDENTIAL    → credential stuffing across all services
```

### 15 Dead-End Fallbacks (rotate when stuck)
```
1.  Try different User-Agent (Googlebot, mobile, curl)
2.  Try HTTP/2
3.  Try IPv6 address
4.  Check Wayback Machine for historical endpoints
5.  Try mobile API endpoints (/api/mobile/)
6.  Try old API versions (/v0, /v1)
7.  Try common backup extensions (.bak, .old, .backup)
8.  Try path normalization bypasses
9.  Try Unicode encoding
10. Try HTTP parameter pollution
11. Try chunked transfer encoding
12. Check certificate transparency logs
13. Try null byte injection
14. Try second-order injection
15. Check third-party integrations
```

---

## 16 Scan Modules

| Module | Description |
|--------|-------------|
| `recon` | Tech stack, SSL, DNS, robots.txt, 20+ sensitive files |
| `headers` | OWASP security headers + CSP/HSTS quality analysis |
| `sqli` | Error-based, boolean blind, time-based, forms, headers |
| `xss` | Reflected, DOM-based, stored indicators, form testing |
| `csrf` | Missing tokens, SameSite analysis, API CSRF |
| `cors` | Origin reflection, wildcard, null origin, credentials |
| `cookies` | HttpOnly, Secure, SameSite flags + session detection |
| `dirs` | 60+ paths, threaded enumeration, tech-based wordlist |
| `lfi` | 16 path traversal payloads + PHP wrappers |
| `ssrf` | AWS metadata, internal IPs, cloud endpoints |
| `idor` | Sequential ID manipulation, ownership verification |
| `rce` | Command injection, SSTI detection |
| `auth` | Default creds, JWT analysis, rate limiting, password policy |
| `api` | Swagger/GraphQL, HTTP methods, auth bypass techniques |
| `info` | HTML comments, error pages, emails, internal IPs, debug mode |
| `ports` | 25 common ports with high-risk service flagging |

---

## Auto Tool Installer

21 tools registered with automatic installation:

```
Network:    nmap, masscan
Web Enum:   gobuster, ffuf, feroxbuster
Web Scan:   nikto, whatweb, wafw00f, nuclei
SQLi:       sqlmap
XSS:        dalfox
OSINT:      theHarvester, amass, subfinder, dnsx
CMS:        wpscan
Bruteforce: hydra
JS:         linkfinder
Utility:    curl, jq, go
```

Each tool has multiple install methods (apt/pip/go/gem/git) and a built-in fallback. The scan **never stops** because a tool is missing.

---

## Report

Professional HTML + PDF report with:
- Risk score and overall risk level
- Severity filter (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Evidence for every finding
- Remediation for every finding
- Module summary table
- Executive summary
- Interactive (click to expand/collapse)

---

## Test Results

```
core/installer.py     Regression: 4/4   Stress: 6/6
core/nde_engine.py    Regression: 15/15 Stress: 10/10
core/console_ui.py    Regression: 13/13 Stress: 10/10
─────────────────────────────────────────────────────
Total:                58 passed  0 failed
```

---

## Requirements

```bash
sudo apt install python3 python3-pip
pip install requests beautifulsoup4 lxml colorama tqdm --break-system-packages
```

---

## Ethical Statement

For **authorized penetration testing** and security research only.
Written permission required before testing any system.

---

## Author

**JarDani** — github.com/JarDaNi686

*"Amon sees the hidden. AmonStrike finds it."*
