<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Modules-25-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tests-236_Passed-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Never_Dead_End-Engine-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge"/>
</p>

<h1 align="center">
  ⚡ AmonStrike
</h1>

<p align="center">
  <b>Hidden Reconnaissance. Precise Strike. Irrefutable Proof.</b><br>
  Professional Bug Bounty Research Infrastructure — from recon to paid report.
</p>

<p align="center">
  Named after <b>Amon</b> — the Egyptian god of the hidden.<br>
  <i>AmonStrike sees what others miss.</i>
</p>

---

## What AmonStrike Does

```
Input:   Any authorized target URL
Output:  Paid bug bounty report with visual proof

Automatically:
  1. Finds the target in bug bounty programs (H1, Bugcrowd, Intigriti)
  2. Validates scope — never scans out of scope
  3. OSINT reconnaissance (subdomains, emails, leaked secrets)
  4. Runs 25 attack modules
  5. Never Dead-End Engine finds what modules miss
  6. Captures screenshot proof of every finding
  7. Generates CVSS v3.1 score for every finding
  8. Produces professional HTML+PDF report
  9. Generates HackerOne submission templates
  10. Tracks earnings and submission status
```

---

## Quick Start

```bash
git clone https://github.com/JarDaNi686/AmonStrike.git
cd AmonStrike
pip install requests beautifulsoup4 flask playwright pillow
playwright install chromium
sudo python3 amonstrike.py
```

---

## Scan Modes

| Mode | Description | Time |
|------|-------------|------|
| `fast` | Essential checks only | ~5 min |
| `normal` | All 25 modules | ~15 min |
| `deep` | All modules + NDE + tool chaining | ~45 min |
| `nde` | Full autonomous Never Dead-End recon | Unlimited |

```bash
# Fast essential check
sudo python3 amonstrike.py --url http://target.com --mode fast

# Full professional scan (default)
sudo python3 amonstrike.py --url http://target.com

# Deep scan with NDE engine
sudo python3 amonstrike.py --url http://target.com --mode deep

# Web dashboard
python3 dashboard/app.py
firefox http://localhost:5000

# Specific modules only
sudo python3 amonstrike.py --url http://target.com --modules sqli,xss,ssrf
```

---

## Architecture

```
amonstrike/
│
├── amonstrike.py              ← Main launcher — wires everything together
│
├── core/
│   ├── nde_engine.py          ← Never Dead-End Engine (25 node types, 15 fallbacks)
│   ├── installer.py           ← Auto tool installer (21 tools, multiple methods)
│   ├── console_ui.py          ← Real-time split terminal UI
│   ├── database.py            ← SQLite persistence (13 tables)
│   ├── scope_validator.py     ← Legal protection — blocks out-of-scope scanning
│   └── scheduler.py           ← Continuous 24/7 scan scheduler
│
├── modules/ (25 total)
│   ├── recon.py               ← Tech stack, SSL, DNS, sensitive files
│   ├── headers.py             ← OWASP security headers + CSP analysis
│   ├── sqli.py                ← Error-based, boolean blind, time-based, UNION
│   ├── xss.py                 ← Reflected, stored, DOM-based
│   ├── ssrf.py                ← AWS metadata, internal network, cloud endpoints
│   ├── lfi.py                 ← Path traversal, PHP wrappers, log poisoning
│   ├── rce.py                 ← Command injection, SSTI detection
│   ├── idor.py                ← Sequential ID manipulation, auth bypass
│   ├── xxe.py                 ← File read, SSRF, SVG, SOAP, content-type switch
│   ├── ssti.py                ← Jinja2, Twig, Freemarker, ERB, Mako
│   ├── http_smuggling.py      ← CL.TE, TE.CL, TE.TE obfuscation
│   ├── jwt_deep.py            ← None alg, weak secret, RS256→HS256, kid injection
│   ├── race_condition.py      ← Payment bypass, rate limit bypass, double-spend
│   ├── cors.py                ← Origin reflection, null origin, credential leakage
│   ├── csrf.py                ← Missing tokens, SameSite, API CSRF
│   ├── auth.py                ← Default creds, rate limiting, JWT, lockout
│   ├── credentials.py         ← Stuffing, spraying, hash identification
│   ├── cookies.py             ← HttpOnly, Secure, SameSite flags
│   ├── dirs.py                ← Directory enumeration, sensitive paths
│   ├── api.py                 ← Swagger, GraphQL, HTTP methods, auth bypass
│   ├── ports.py               ← 25 common ports, high-risk service detection
│   ├── info.py                ← HTML comments, error pages, debug info
│   ├── osint.py               ← theHarvester, crt.sh, Wayback, GitHub dorking
│   ├── waf.py                 ← 12 WAF signatures, 10 bypass techniques
│   └── takeover.py            ← 16 services, S3/Azure misconfiguration
│
├── bounty/
│   ├── platform_fetcher.py    ← HackerOne, Bugcrowd, Intigriti, direct programs
│   └── program_ranker.py      ← S/A/B/C/D tier scoring, earning estimates
│
├── verify/
│   ├── screenshot.py          ← Headless Chromium — visual proof of every finding
│   ├── cvss_calculator.py     ← Full CVSS v3.1 implementation
│   ├── evidence_collector.py  ← HTTP request/response capture
│   └── poc_generator.py       ← Working exploit scripts
│
├── reports/
│   ├── poc_report.py          ← Comprehensive PoC report with screenshots
│   ├── generator.py           ← HTML + PDF + D3.js attack graph
│   └── hackerone_format.py    ← HackerOne submission format
│
└── dashboard/
    └── app.py                 ← Flask web dashboard (6 pages, SSE live logs)
```

---

## Never Dead-End Engine

Every finding is a node. Every node triggers the next attack. No dead ends.

```
25 Node Types:
  DOMAIN · SUBDOMAIN · IP_ADDRESS · OPEN_PORT · WEB_SERVICE
  LOGIN_PAGE · API_ENDPOINT · ADMIN_PANEL · JS_FILE · FORM
  PARAMETER · COOKIE · EMAIL · CREDENTIAL · VULNERABILITY
  TECHNOLOGY · ERROR_PAGE · FILE_UPLOAD · REDIRECT · DIRECTORY
  DATABASE_ERROR · WAF_DETECTED · CMS_DETECTED · JWT_TOKEN · API_KEY

15 Dead-End Fallbacks:
  1.  Different User-Agent (Googlebot, mobile, curl)
  2.  HTTP/2 protocol switch
  3.  IPv6 address
  4.  Wayback Machine historical endpoints
  5.  Mobile API endpoints (/api/mobile/)
  6.  Old API versions (/v0, /v1)
  7.  Backup file extensions (.bak, .old, .backup)
  8.  Path normalization bypasses
  9.  Unicode encoding
  10. HTTP Parameter Pollution
  11. Chunked transfer encoding
  12. Certificate transparency logs
  13. Null byte injection
  14. Second-order injection
  15. Third-party integrations
```

---

## Proof of Exploit Report

Every finding gets full visual proof — irrefutable evidence for bug bounty submission.

### What Each Finding Contains

| Section | Content |
|---------|---------|
| **CVSS v3.1** | Full score + vector string (auto-calculated) |
| **Screenshots** | 2–5 annotated browser screenshots per finding |
| **Step-by-Step** | Numbered reproduction steps specific to vuln type |
| **HTTP Capture** | Full request + response side by side |
| **Commands** | curl, sqlmap, dalfox, nmap — one-click copy |
| **Exploit Script** | Working Python PoC script (100–200 lines) |
| **Impact Analysis** | Business + Technical + Worst Case + Attack Chain |
| **Code Diff** | Vulnerable code vs secure code side by side |
| **Remediation** | Specific fix with code examples |

### Screenshot Captures Per Module

```
SQLi:         Baseline → Error → Boolean TRUE → Boolean FALSE → UNION extraction
XSS:          Baseline → Alert dialog → Reflected source → Cookie theft → SVG bypass
LFI:          Baseline → /etc/passwd → URL-encoded → /etc/hosts → PHP wrapper
Auth:         Login page → Credentials filling → Authenticated dashboard → Cookie inspector
CORS:         Baseline → Cross-origin exploit page
Headers:      Baseline → Clickjacking proof
Takeover:     Dangling subdomain → Attacker-controlled content
JWT:          Full attack chain visualization
XXE:          File read proof
SSTI:         Template evaluation proof
Ports:        Port scan results visualization
```

---

## Bug Bounty Integration

```
Platforms supported:
  HackerOne    → API integration, scope parsing, submission format
  Bugcrowd     → Program fetching, VRT taxonomy
  Intigriti    → European programs
  Direct       → NASA, DoD, Google, Microsoft, Apple + practice targets

Program ranking:
  S-Tier: Score ≥80  — Run immediately
  A-Tier: Score ≥65  — Run this week
  B-Tier: Score ≥50  — Weekend project
  C-Tier: Score ≥35  — Low priority
  D-Tier: Score <35  — Skip

Scoring factors (100 points):
  Bounty potential    30pts
  Automation allowed  20pts
  Scope size          15pts
  Response time       15pts
  Competition level   10pts
  Platform trust      10pts
```

---

## Dashboard

```bash
python3 dashboard/app.py
firefox http://localhost:5000
```

Six pages: Dashboard · Scan · Findings · Programs · Earnings · Submissions

- Real-time scan log streaming (Server-Sent Events)
- One-click scan launch with mode selection
- Program leaderboard with tier colors
- Earnings tracker by platform and severity
- Submission status tracking

---

## Legal & Ethical Use

AmonStrike enforces legal compliance automatically:

```
✓ Scope validation before every request
✓ Out-of-scope blocked automatically
✓ Rate limiting (10 req/s max per target)
✓ Hardcoded exclusions: *.gov, *.mil, cloudflare.com, etc.
✓ Legal disclaimer generated for every report

ONLY use on:
  - Systems you own
  - Systems with explicit written permission
  - Open bug bounty programs (within their defined scope)
  - Deliberately vulnerable practice targets (DVWA, vulnweb.com, HackTheBox)
```

---

## Test Results

```
Component                  Regression    Stress
─────────────────────────────────────────────────
core/database.py           16/16         6/6
core/scope_validator.py    18/18         5/5
core/scheduler.py          12/12         —
bounty/platform_fetcher.py 10/10         —
bounty/program_ranker.py   14/14         —
dashboard/app.py           13/13         —
verify/cvss_calculator.py  14/14         —
verify/evidence_collector  13/13         —
verify/poc_generator.py    55/55         —
verify/screenshot.py       23/23         —
reports/hackerone_format   13/13         —
reports/poc_report.py      24/24         —
─────────────────────────────────────────────────
TOTAL                      236 passed    0 failed
```

---

## Practice Targets (Legal — No Permission Needed)

```
testphp.vulnweb.com      Acunetix PHP test — SQLi, XSS, LFI confirmed
testaspnet.vulnweb.com   ASP.NET test site
testasp.vulnweb.com      Classic ASP test site
demo.testfire.net        IBM Altoro Mutual bank demo
hackthebox.com           Legal CTF machines
tryhackme.com            Guided legal hacking labs
```

---

## Requirements

```bash
# Python packages
pip install requests beautifulsoup4 lxml flask pillow playwright

# Playwright browser
playwright install chromium

# Optional (auto-installed by AmonStrike)
apt install nmap sqlmap dalfox gobuster ffuf amass subfinder
```

---

## Author

**JarDani** — github.com/JarDaNi686

*"Amon sees the hidden. AmonStrike finds it. The report proves it."*
