#!/usr/bin/env python3
"""
AmonStrike — Hidden Reconnaissance, Precise Strike
Author: JarDani
Version: 1.0

Egyptian god Amon sees the hidden. AmonStrike finds the hidden vulnerabilities.

Usage:
    sudo python3 amonstrike.py
    sudo python3 amonstrike.py --url http://target.com
    sudo python3 amonstrike.py --url http://target.com --modules all
    sudo python3 amonstrike.py --url http://target.com --modules recon,sqli,xss
"""

import os
import sys
import time
import json
import argparse
import threading
from datetime import datetime
from urllib.parse import urlparse

# ── Color codes ──────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
D  = "\033[90m"
X  = "\033[0m"
BLD = "\033[1m"

BANNER = f"""
{D}  ════════════════════════════════════════════════════════════════════{X}
{R}{BLD}
    ░█████╗░███╗░░░███╗░█████╗░███╗░░██╗░██████╗████████╗██████╗░██╗██╗░░██╗███████╗
    ██╔══██╗████╗░████║██╔══██╗████╗░██║██╔════╝╚══██╔══╝██╔══██╗██║██║░██╔╝██╔════╝
    ███████║██╔████╔██║██║░░██║██╔██╗██║╚█████╗░░░░██║░░░██████╔╝██║█████═╝░█████╗░░
    ██╔══██║██║╚██╔╝██║██║░░██║██║╚████║░╚═══██╗░░░██║░░░██╔══██╗██║██╔═██╗░██╔══╝░░
    ██║░░██║██║░╚═╝░██║╚█████╔╝██║░╚███║██████╔╝░░░██║░░░██║░░██║██║██║░╚██╗███████╗
    ╚═╝░░╚═╝╚═╝░░░░╚═╝░╚════╝░╚═╝░░╚══╝╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚═╝░░╚═╝╚══════╝
{X}
{D}         Hidden Reconnaissance. Precise Strike. Professional Report.{X}
{D}  ════════════════════════════════════════════════════════════════════{X}
{D}         Author: JarDani    Version: 1.0    Bug Bounty Edition{X}
{D}  ════════════════════════════════════════════════════════════════════{X}
"""

# ── Available modules ────────────────────────────────────────
MODULES = {
    "recon":      "Reconnaissance — headers, tech stack, DNS, WHOIS, SSL",
    "ports":      "Port scanning — open ports and services",
    "dirs":       "Directory/file enumeration — hidden paths",
    "api":        "API endpoint discovery and testing",
    "auth":       "Authentication testing — login, JWT, session",
    "sqli":       "SQL Injection — GET/POST/headers",
    "xss":        "Cross-Site Scripting — reflected/stored",
    "csrf":       "CSRF — token detection and bypass",
    "idor":       "IDOR — Insecure Direct Object Reference",
    "ssrf":       "SSRF — Server-Side Request Forgery",
    "lfi":        "LFI/RFI — Local/Remote File Inclusion",
    "headers":    "Security headers analysis",
    "cookies":    "Cookie security flags analysis",
    "cors":       "CORS misconfiguration",
    "rce":        "Command injection / RCE detection",
    "info":       "Information disclosure — errors, comments, metadata",
}

def log(msg, level="*", color=None):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"*": D, "!": R, "+": G, "~": Y, "i": C}
    c = color or colors.get(level, D)
    print(f"[{ts}] {c}[AS/{level}]{X} {msg}")

def get_input(prompt, default=None):
    if default:
        result = input(f"{W}{prompt}{X} [{D}{default}{X}]: ").strip()
        return result if result else default
    return input(f"{W}{prompt}{X}: ").strip()

def validate_url(url):
    """Validate and normalize URL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return url.rstrip("/")
    except:
        return None

def select_modules():
    """Interactive module selection."""
    print(f"\n{D}  Available modules:{X}\n")
    for i, (name, desc) in enumerate(MODULES.items(), 1):
        print(f"  {D}[{i:2d}]{X} {R}{name:<12}{X} {D}─{X} {desc}")
    print(f"\n  {D}[{' 0':2s}]{X} {G}all{X}         {D}─{X} Run all modules")
    print()

    choice = get_input("  Select modules (e.g. 1,3,5 or 'all' or module names)", "all")

    if choice.lower() == "all" or choice == "0":
        return list(MODULES.keys())

    selected = []
    # Handle comma-separated numbers or names
    for part in choice.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(MODULES):
                selected.append(list(MODULES.keys())[idx])
        elif part in MODULES:
            selected.append(part)

    return selected if selected else list(MODULES.keys())

def print_summary(url, modules, output_dir):
    """Print attack configuration summary."""
    print()
    print(f"{D}  ┌{'─'*60}┐{X}")
    print(f"{D}  │{X}{R} MISSION PARAMETERS{X}{D}{'':>41}│{X}")
    print(f"{D}  ├{'─'*60}┤{X}")
    print(f"{D}  │{X}  {W}Target URL:{X}    {R}{url}{X}")
    print(f"{D}  │{X}  {W}Modules:{X}       {G}{', '.join(modules)}{X}")
    print(f"{D}  │{X}  {W}Output:{X}        {C}{output_dir}{X}")
    print(f"{D}  │{X}  {W}Started:{X}       {D}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    print(f"{D}  └{'─'*60}┘{X}")
    print()

def run_module(name, url, session_data, results):
    """Dynamically load and run a module."""
    try:
        if name == "recon":
            from modules.recon import ReconModule
            m = ReconModule(url, session_data)
        elif name == "ports":
            from modules.ports import PortModule
            m = PortModule(url, session_data)
        elif name == "dirs":
            from modules.dirs import DirModule
            m = DirModule(url, session_data)
        elif name == "api":
            from modules.api import ApiModule
            m = ApiModule(url, session_data)
        elif name == "auth":
            from modules.auth import AuthModule
            m = AuthModule(url, session_data)
        elif name == "sqli":
            from modules.sqli import SqliModule
            m = SqliModule(url, session_data)
        elif name == "xss":
            from modules.xss import XssModule
            m = XssModule(url, session_data)
        elif name == "csrf":
            from modules.csrf import CsrfModule
            m = CsrfModule(url, session_data)
        elif name == "idor":
            from modules.idor import IdorModule
            m = IdorModule(url, session_data)
        elif name == "ssrf":
            from modules.ssrf import SsrfModule
            m = SsrfModule(url, session_data)
        elif name == "lfi":
            from modules.lfi import LfiModule
            m = LfiModule(url, session_data)
        elif name == "headers":
            from modules.headers import HeadersModule
            m = HeadersModule(url, session_data)
        elif name == "cookies":
            from modules.cookies import CookiesModule
            m = CookiesModule(url, session_data)
        elif name == "cors":
            from modules.cors import CorsModule
            m = CorsModule(url, session_data)
        elif name == "rce":
            from modules.rce import RceModule
            m = RceModule(url, session_data)
        elif name == "info":
            from modules.info import InfoModule
            m = InfoModule(url, session_data)
        else:
            return

        findings = m.run()
        results[name] = findings

    except ImportError as e:
        log(f"Module {name} not available: {e}", "~")
        results[name] = {"error": str(e), "findings": []}
    except Exception as e:
        log(f"Module {name} error: {e}", "!")
        results[name] = {"error": str(e), "findings": []}

def main():
    print(BANNER)

    # Check root
    if os.geteuid() != 0:
        print(f"{R}[!]{X} Run with sudo: sudo python3 amonstrike.py")
        sys.exit(1)

    # Parse args
    parser = argparse.ArgumentParser(description="AmonStrike — Bug Bounty Recon Framework")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--modules", help="Modules to run (comma-separated or 'all')")
    parser.add_argument("--output", help="Output directory", default="output")
    parser.add_argument("--threads", help="Number of threads", type=int, default=5)
    parser.add_argument("--timeout", help="Request timeout (seconds)", type=int, default=10)
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies string")
    parser.add_argument("--headers", help="Extra headers JSON string")
    parser.add_argument("--wordlist", help="Custom wordlist for dir enumeration")
    args = parser.parse_args()

    # Get target URL
    if args.url:
        url = validate_url(args.url)
        if not url:
            print(f"{R}[!]{X} Invalid URL: {args.url}")
            sys.exit(1)
    else:
        print(f"{D}  Configure your scan:{X}\n")
        raw_url = get_input("  Target URL")
        url = validate_url(raw_url)
        if not url:
            print(f"{R}[!]{X} Invalid URL")
            sys.exit(1)

    # Get modules
    if args.modules:
        if args.modules.lower() == "all":
            modules = list(MODULES.keys())
        else:
            modules = [m.strip() for m in args.modules.split(",") if m.strip() in MODULES]
    else:
        modules = select_modules()

    # Session data shared across modules
    session_data = {
        "url":      url,
        "parsed":   urlparse(url),
        "timeout":  args.timeout,
        "threads":  args.threads,
        "proxy":    {"http": args.proxy, "https": args.proxy} if args.proxy else None,
        "cookies":  args.cookies or "",
        "headers":  json.loads(args.headers) if args.headers else {},
        "wordlist": args.wordlist,
        "start_time": datetime.now().isoformat(),
    }

    # Output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    parsed = urlparse(url)
    safe_host = parsed.netloc.replace(":", "_").replace(".", "_")
    output_dir = os.path.join(args.output, f"{safe_host}_{ts}")
    os.makedirs(output_dir, exist_ok=True)
    session_data["output_dir"] = output_dir

    print_summary(url, modules, output_dir)

    confirm = input(f"  {W}Start scan? (Enter to continue / Ctrl+C to cancel){X}: ")
    print()

    # ── Run modules ──────────────────────────────────────────
    results = {}
    total = len(modules)

    log(f"Starting AmonStrike against {R}{url}{X}", "+")
    log(f"Running {total} modules — {', '.join(modules)}", "i")
    print()

    for i, module in enumerate(modules, 1):
        log(f"[{i}/{total}] Running module: {R}{module}{X} — {D}{MODULES.get(module, '')}{X}", "*")
        run_module(module, url, session_data, results)

    print()
    log("All modules complete — generating report", "+")

    # ── Generate report ──────────────────────────────────────
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from reports.generator import ReportGenerator

    gen = ReportGenerator(url, modules, results, session_data, output_dir)
    html_path, pdf_path = gen.generate()

    # ── Summary ──────────────────────────────────────────────
    print()
    print(f"{D}  ════════════════════════════════════════════════════════{X}")
    print(f"{R}{BLD}  AMONSTRIKE COMPLETE{X}")
    print(f"{D}  ════════════════════════════════════════════════════════{X}")

    # Count findings by severity
    critical = high = medium = low = info_count = 0
    for mod_results in results.values():
        for finding in mod_results.get("findings", []):
            sev = finding.get("severity", "").upper()
            if sev == "CRITICAL": critical += 1
            elif sev == "HIGH": high += 1
            elif sev == "MEDIUM": medium += 1
            elif sev == "LOW": low += 1
            elif sev == "INFO": info_count += 1

    print(f"\n  {W}Findings Summary:{X}")
    print(f"  {R}Critical: {critical}{X}  {R}High: {high}{X}  {Y}Medium: {medium}{X}  {G}Low: {low}{X}  {D}Info: {info_count}{X}")
    print(f"\n  {W}Reports:{X}")
    print(f"  {C}HTML:{X} {html_path}")
    if pdf_path:
        print(f"  {C}PDF: {X} {pdf_path}")
    print(f"\n  {D}Open report: firefox {html_path}{X}")
    print(f"{D}  ════════════════════════════════════════════════════════{X}\n")

if __name__ == "__main__":
    main()
