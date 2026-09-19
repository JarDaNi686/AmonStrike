#!/usr/bin/env python3
"""
AmonStrike — Kali Tools Maximizer

Discovers ALL installed security tools on Kali Linux.
Maps each tool to its vulnerability class.
Auto-installs missing critical tools (apt / go install / pip).
Runs the right tool for each phase.

Quality over speed — every tool gets full depth, no shortcuts.
"""
import os, sys, json, shutil, subprocess, time
from pathlib import Path
from typing import Callable

# ─────────────────────────────────────────────────────────────
# Complete tool registry — every useful Kali security tool
# Format: name → {category, install, cmd_check, description}
# ─────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    # ── Subdomain & Recon ─────────────────────────────────────
    "subfinder":    {"cat":"recon",     "install":"go:projectdiscovery/subfinder/v2/cmd/subfinder",
                     "desc":"passive subdomain enum"},
    "amass":        {"cat":"recon",     "install":"go:github.com/owasp-amass/amass/v4/...",
                     "desc":"deep subdomain OSINT"},
    "assetfinder":  {"cat":"recon",     "install":"go:github.com/tomnomnom/assetfinder",
                     "desc":"fast subdomain finder"},
    "findomain":    {"cat":"recon",     "install":"apt:findomain",
                     "desc":"subdomain finder (Rust)"},
    "chaos":        {"cat":"recon",     "install":"go:github.com/projectdiscovery/chaos-client/cmd/chaos",
                     "desc":"ProjectDiscovery chaos dataset"},
    "shuffledns":   {"cat":"recon",     "install":"go:github.com/projectdiscovery/shuffledns/cmd/shuffledns",
                     "desc":"DNS bruteforce + validation"},
    "dnsx":         {"cat":"recon",     "install":"go:github.com/projectdiscovery/dnsx/cmd/dnsx",
                     "desc":"DNS toolkit"},
    "massdns":      {"cat":"recon",     "install":"apt:massdns",
                     "desc":"high-performance DNS resolver"},
    "puredns":      {"cat":"recon",     "install":"go:github.com/d3mondev/puredns/v2",
                     "desc":"fast DNS bruteforce"},

    # ── HTTP Probing & Fingerprinting ─────────────────────────
    "httpx":        {"cat":"probe",     "install":"go:github.com/projectdiscovery/httpx/cmd/httpx",
                     "desc":"HTTP probing toolkit"},
    "httprobe":     {"cat":"probe",     "install":"go:github.com/tomnomnom/httprobe",
                     "desc":"simple HTTP prober"},
    "whatweb":      {"cat":"probe",     "install":"apt:whatweb",
                     "desc":"tech fingerprinting"},
    "wappalyzer":   {"cat":"probe",     "install":"npm:wappalyzer",
                     "desc":"tech detection"},
    "wafw00f":      {"cat":"probe",     "install":"pip:wafw00f",
                     "desc":"WAF detection"},
    "webanalyze":   {"cat":"probe",     "install":"go:github.com/rverton/webanalyze/cmd/webanalyze",
                     "desc":"Wappalyzer-based fingerprint"},

    # ── Port Scanning ─────────────────────────────────────────
    "nmap":         {"cat":"portscan",  "install":"apt:nmap",
                     "desc":"network scanner"},
    "masscan":      {"cat":"portscan",  "install":"apt:masscan",
                     "desc":"ultra-fast port scanner"},
    "rustscan":     {"cat":"portscan",  "install":"cargo:rustscan",
                     "desc":"Rust port scanner (fast)"},
    "naabu":        {"cat":"portscan",  "install":"go:github.com/projectdiscovery/naabu/v2/cmd/naabu",
                     "desc":"fast port scanner"},

    # ── Web Crawling & Endpoint Discovery ─────────────────────
    "katana":       {"cat":"crawl",     "install":"go:github.com/projectdiscovery/katana/cmd/katana",
                     "desc":"next-gen web crawler"},
    "gospider":     {"cat":"crawl",     "install":"go:github.com/jaeles-project/gospider",
                     "desc":"fast web spider"},
    "hakrawler":    {"cat":"crawl",     "install":"go:github.com/hakluke/hakrawler",
                     "desc":"simple fast crawler"},
    "gau":          {"cat":"crawl",     "install":"go:github.com/lc/gau/v2/cmd/gau",
                     "desc":"historical URLs (wayback+otx+commoncrawl)"},
    "waybackurls":  {"cat":"crawl",     "install":"go:github.com/tomnomnom/waybackurls",
                     "desc":"Wayback Machine URLs"},
    "gauplus":      {"cat":"crawl",     "install":"go:github.com/bp0lr/gauplus",
                     "desc":"gau with extra sources"},
    "urlfinder":    {"cat":"crawl",     "install":"go:github.com/projectdiscovery/urlfinder/cmd/urlfinder",
                     "desc":"JS URL extractor"},

    # ── Directory & Parameter Fuzzing ─────────────────────────
    "ffuf":         {"cat":"fuzz",      "install":"go:github.com/ffuf/ffuf/v2",
                     "desc":"fast web fuzzer"},
    "gobuster":     {"cat":"fuzz",      "install":"apt:gobuster",
                     "desc":"dir/file/dns bruteforcer"},
    "feroxbuster":  {"cat":"fuzz",      "install":"apt:feroxbuster",
                     "desc":"recursive content discovery"},
    "dirsearch":    {"cat":"fuzz",      "install":"pip:dirsearch",
                     "desc":"web path discovery"},
    "wfuzz":        {"cat":"fuzz",      "install":"apt:wfuzz",
                     "desc":"web application fuzzer"},
    "arjun":        {"cat":"fuzz",      "install":"pip:arjun",
                     "desc":"HTTP parameter discovery"},
    "x8":           {"cat":"fuzz",      "install":"cargo:x8",
                     "desc":"parameter discovery (Rust)"},
    "kiterunner":   {"cat":"fuzz",      "install":"go:github.com/assetnote/kiterunner/cmd/kr",
                     "desc":"API route discovery"},

    # ── Vulnerability Scanning ────────────────────────────────
    "nuclei":       {"cat":"vuln",      "install":"go:github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
                     "desc":"template-based vuln scanner (12k+ templates)"},
    "nikto":        {"cat":"vuln",      "install":"apt:nikto",
                     "desc":"web server scanner"},
    "jaeles":       {"cat":"vuln",      "install":"go:github.com/jaeles-project/jaeles",
                     "desc":"web app testing framework"},
    "skipfish":     {"cat":"vuln",      "install":"apt:skipfish",
                     "desc":"web app recon tool"},

    # ── SQL Injection ─────────────────────────────────────────
    "sqlmap":       {"cat":"sqli",      "install":"apt:sqlmap",
                     "desc":"automatic SQL injection"},
    "ghauri":       {"cat":"sqli",      "install":"pip:ghauri",
                     "desc":"advanced SQL injection (sqlmap alternative)"},

    # ── XSS ───────────────────────────────────────────────────
    "dalfox":       {"cat":"xss",       "install":"go:github.com/hahwul/dalfox/v2",
                     "desc":"fast XSS scanner"},
    "xsser":        {"cat":"xss",       "install":"apt:xsser",
                     "desc":"XSS framework"},
    "xsstrike":     {"cat":"xss",       "install":"pip:xsstrike",
                     "desc":"XSS detection suite"},

    # ── SSRF & Open Redirect ──────────────────────────────────
    "ssrfmap":      {"cat":"ssrf",      "install":"git:https://github.com/swisskyrepo/SSRFmap",
                     "desc":"SSRF exploitation framework"},
    "interactsh-client": {"cat":"ssrf", "install":"go:github.com/projectdiscovery/interactsh/cmd/interactsh-client",
                     "desc":"OAST interaction server"},

    # ── Secret & Token Detection ──────────────────────────────
    "trufflehog":   {"cat":"secrets",   "install":"go:github.com/trufflesecurity/trufflehog/v3",
                     "desc":"finds secrets in git/code"},
    "gitleaks":     {"cat":"secrets",   "install":"go:github.com/gitleaks/gitleaks/v8",
                     "desc":"git secret scanner"},
    "secretfinder": {"cat":"secrets",   "install":"pip:secretfinder",
                     "desc":"JS secret extractor"},
    "grep":         {"cat":"secrets",   "install":"builtin",
                     "desc":"pattern search"},

    # ── JS Analysis ───────────────────────────────────────────
    "linkfinder":   {"cat":"js",        "install":"pip:linkfinder",
                     "desc":"endpoint extractor from JS"},
    "jsluice":      {"cat":"js",        "install":"go:github.com/BishopFox/jsluice/cmd/jsluice",
                     "desc":"JS static analysis"},
    "retire":       {"cat":"js",        "install":"npm:retire",
                     "desc":"finds outdated/vuln JS libs"},

    # ── Auth & Session ────────────────────────────────────────
    "jwt_tool":     {"cat":"auth",      "install":"pip:jwt_tool",
                     "desc":"JWT attack toolkit"},
    "hydra":        {"cat":"auth",      "install":"apt:hydra",
                     "desc":"login brute-force"},
    "medusa":       {"cat":"auth",      "install":"apt:medusa",
                     "desc":"parallel login brute-force"},
    "patator":      {"cat":"auth",      "install":"apt:patator",
                     "desc":"multi-protocol brute-forcer"},

    # ── Cloud & Infrastructure ────────────────────────────────
    "awscli":       {"cat":"cloud",     "install":"pip:awscli",
                     "desc":"AWS CLI (SSRF→AWS metadata)"},
    "cloudflair":   {"cat":"cloud",     "install":"pip:cloudflair",
                     "desc":"Cloudflare origin IP finder"},
    "cloudbrute":   {"cat":"cloud",     "install":"go:github.com/0xsha/cloudbrute",
                     "desc":"cloud storage bruteforce"},
    "s3scanner":    {"cat":"cloud",     "install":"pip:s3scanner",
                     "desc":"S3 bucket scanner"},

    # ── Proxy & Interception ──────────────────────────────────
    "burpsuite":    {"cat":"proxy",     "install":"apt:burpsuite",
                     "desc":"web proxy/scanner"},
    "mitmproxy":    {"cat":"proxy",     "install":"pip:mitmproxy",
                     "desc":"interactive MITM proxy"},
    "proxify":      {"cat":"proxy",     "install":"go:github.com/projectdiscovery/proxify/cmd/proxify",
                     "desc":"HTTP/HTTPS traffic proxy"},

    # ── Network & Protocol ────────────────────────────────────
    "curl":         {"cat":"network",   "install":"builtin",
                     "desc":"HTTP client"},
    "wget":         {"cat":"network",   "install":"builtin",
                     "desc":"HTTP downloader"},
    "netcat":       {"cat":"network",   "install":"apt:netcat-openbsd",
                     "desc":"network tool"},

    # ── Exploitation Frameworks ───────────────────────────────
    "metasploit":   {"cat":"exploit",   "install":"apt:metasploit-framework",
                     "desc":"exploitation framework"},
    "msfconsole":   {"cat":"exploit",   "install":"apt:metasploit-framework",
                     "desc":"Metasploit console"},
    "commix":       {"cat":"exploit",   "install":"apt:commix",
                     "desc":"command injection exploitation"},
    "tplmap":       {"cat":"exploit",   "install":"pip:tplmap",
                     "desc":"SSTI exploitation"},

    # ── Wordlists & Payloads ──────────────────────────────────
    "cewl":         {"cat":"wordlist",  "install":"apt:cewl",
                     "desc":"custom wordlist generator"},
    "crunch":       {"cat":"wordlist",  "install":"apt:crunch",
                     "desc":"wordlist generator"},
}

# Tools required for quality scanning (auto-install if missing)
CRITICAL_TOOLS = {
    "nuclei", "subfinder", "httpx", "ffuf", "katana",
    "dalfox", "gau", "waybackurls", "arjun", "dnsx",
    "nmap", "sqlmap", "nikto", "gobuster", "whatweb",
    "trufflehog", "gitleaks", "wafw00f", "naabu",
}

# Maps vulnerability class → tools to run
VULN_TOOL_MAP = {
    "sqli":     ["sqlmap", "ghauri"],
    "xss":      ["dalfox", "xsstrike", "xsser"],
    "ssrf":     ["nuclei", "interactsh-client"],
    "ssti":     ["tplmap", "nuclei"],
    "idor":     ["ffuf", "arjun"],
    "rce":      ["commix", "nuclei", "metasploit"],
    "lfi":      ["nuclei", "ffuf", "gobuster"],
    "open_redirect": ["nuclei", "dalfox"],
    "secrets":  ["trufflehog", "gitleaks", "secretfinder"],
    "js_analysis":   ["linkfinder", "jsluice", "retire"],
    "subdomain": ["subfinder", "amass", "assetfinder", "dnsx", "shuffledns"],
    "ports":    ["nmap", "naabu", "masscan", "rustscan"],
    "crawl":    ["katana", "gospider", "gau", "waybackurls", "hakrawler"],
    "params":   ["arjun", "x8", "ffuf"],
    "vuln_scan":["nuclei", "nikto", "jaeles"],
    "waf":      ["wafw00f", "nuclei"],
    "auth":     ["hydra", "jwt_tool", "nuclei"],
    "cloud":    ["s3scanner", "cloudbrute", "nuclei"],
}


class KaliToolsMaximizer:
    """
    Discovers, manages, and runs ALL available Kali tools.
    Quality-first: every tool runs at maximum depth.
    """

    def __init__(self):
        self.available = {}
        self.missing   = {}
        self._scan_installed()

    def _scan_installed(self):
        """Detect all installed tools."""
        for name, meta in TOOL_REGISTRY.items():
            if meta["install"] == "builtin":
                self.available[name] = shutil.which(name) or name
                continue
            path = shutil.which(name)
            # Also check common install locations
            if not path:
                for loc in [f"/usr/local/bin/{name}", f"/usr/bin/{name}",
                            f"{Path.home()}/go/bin/{name}",
                            f"/opt/tools/{name}/{name}"]:
                    if Path(loc).exists():
                        path = loc
                        break
            if path:
                self.available[name] = path
            else:
                self.missing[name] = meta

    def status_report(self) -> dict:
        """Return installed/missing counts by category."""
        report = {"available": {}, "missing": {}, "by_category": {}}
        for name, path in self.available.items():
            cat = TOOL_REGISTRY.get(name, {}).get("cat", "other")
            report["available"][name] = path
            report["by_category"].setdefault(cat, {"have": [], "need": []})["have"].append(name)
        for name, meta in self.missing.items():
            cat = meta.get("cat", "other")
            report["missing"][name] = meta["install"]
            report["by_category"].setdefault(cat, {"have": [], "need": []})["need"].append(name)
        return report

    def print_status(self):
        """Print Rich table of tool status."""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            console = Console()
        except ImportError:
            self._print_simple_status()
            return

        table = Table(title="Kali Tools Status", header_style="bold cyan", border_style="dim")
        table.add_column("Tool",       style="white",      width=18)
        table.add_column("Category",   style="cyan",       width=12)
        table.add_column("Status",     width=10)
        table.add_column("Description",style="dim",        width=40)

        for name in sorted(TOOL_REGISTRY.keys()):
            meta   = TOOL_REGISTRY[name]
            status = "[green]✓ ready[/green]" if name in self.available else "[red]✗ missing[/red]"
            is_crit = "[bold]" if name in CRITICAL_TOOLS else ""
            table.add_row(f"{is_crit}{name}", meta["cat"], status, meta["desc"])

        console.print(table)
        console.print(
            f"\n[green]{len(self.available)} tools ready[/green]  "
            f"[red]{len(self.missing)} missing[/red]  "
            f"[yellow]{len([m for m in self.missing if m in CRITICAL_TOOLS])} critical missing[/yellow]"
        )

    def _print_simple_status(self):
        print(f"Available ({len(self.available)}): {', '.join(sorted(self.available))}")
        print(f"Missing   ({len(self.missing)}): {', '.join(sorted(self.missing))}")

    def install_missing_critical(self, dry_run: bool = False) -> list:
        """
        Install missing critical tools automatically.
        Returns list of (tool, success) tuples.
        """
        results = []
        for name in CRITICAL_TOOLS:
            if name in self.available:
                continue
            meta    = TOOL_REGISTRY.get(name, {})
            install = meta.get("install", "")
            if not install or install == "builtin":
                continue

            print(f"[INSTALL] {name} ({install})")
            if dry_run:
                results.append((name, "dry_run"))
                continue

            ok = self._install_tool(name, install)
            results.append((name, "ok" if ok else "failed"))
            if ok:
                path = shutil.which(name)
                if path:
                    self.available[name] = path
                    self.missing.pop(name, None)
        return results

    def _install_tool(self, name: str, install_spec: str) -> bool:
        """Install a single tool."""
        try:
            if install_spec.startswith("go:"):
                pkg = install_spec[3:]
                cmd = ["go", "install", f"github.com/{pkg}@latest"]
                r   = subprocess.run(cmd, capture_output=True, timeout=120)
                return r.returncode == 0

            elif install_spec.startswith("apt:"):
                pkg = install_spec[4:]
                cmd = ["sudo", "apt-get", "install", "-y", pkg]
                r   = subprocess.run(cmd, capture_output=True, timeout=120)
                return r.returncode == 0

            elif install_spec.startswith("pip:"):
                pkg = install_spec[4:]
                cmd = [sys.executable, "-m", "pip", "install", pkg, "-q"]
                r   = subprocess.run(cmd, capture_output=True, timeout=60)
                return r.returncode == 0

            elif install_spec.startswith("npm:"):
                pkg = install_spec[4:]
                cmd = ["npm", "install", "-g", pkg]
                r   = subprocess.run(cmd, capture_output=True, timeout=60)
                return r.returncode == 0

        except Exception as e:
            print(f"[INSTALL] {name} failed: {e}")
        return False

    def get_tools_for_phase(self, phase: str) -> dict:
        """
        Return available tools for a given vulnerability phase.
        phase = "recon" | "sqli" | "xss" | "crawl" | etc.
        Returns {tool_name: tool_path}
        """
        target_tools = VULN_TOOL_MAP.get(phase, [])
        # Also include tools by category
        cat_tools = [n for n, m in TOOL_REGISTRY.items() if m.get("cat") == phase]
        all_tools = list(dict.fromkeys(target_tools + cat_tools))
        return {t: self.available[t] for t in all_tools if t in self.available}

    def get_all_available(self) -> dict:
        """Return all available tools."""
        return dict(self.available)

    def run_tool_quality(self, tool: str, cmd: list, timeout: int = 300,
                         output_file: str = None) -> dict:
        """
        Run a tool with quality settings (no speed shortcuts).
        Returns {stdout, stderr, returncode, findings}.
        """
        if tool not in self.available:
            return {"error": f"{tool} not available", "findings": []}

        try:
            if output_file:
                with open(output_file, "w") as fh:
                    result = subprocess.run(
                        cmd, stdout=fh, stderr=subprocess.PIPE,
                        timeout=timeout, text=True
                    )
                stdout = Path(output_file).read_text() if Path(output_file).exists() else ""
            else:
                result = subprocess.run(
                    cmd, capture_output=True, timeout=timeout, text=True
                )
                stdout = result.stdout

            return {
                "tool":       tool,
                "returncode": result.returncode,
                "stdout":     stdout[:50000],
                "stderr":     result.stderr[:5000] if hasattr(result, 'stderr') else "",
                "findings":   self._parse_findings(tool, stdout),
            }
        except subprocess.TimeoutExpired:
            return {"tool": tool, "error": f"timeout ({timeout}s)", "findings": []}
        except Exception as e:
            return {"tool": tool, "error": str(e), "findings": []}

    def _parse_findings(self, tool: str, output: str) -> list:
        """Extract structured findings from tool output."""
        findings = []
        lines    = output.splitlines()

        if tool == "nuclei":
            for line in lines:
                if line.startswith("[") and "] [" in line:
                    findings.append({"tool": "nuclei", "raw": line,
                                     "severity": self._nuclei_severity(line)})

        elif tool in ("subfinder", "assetfinder", "amass"):
            for line in lines:
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    findings.append({"tool": tool, "type": "subdomain", "value": line})

        elif tool == "httpx":
            for line in lines:
                if line.startswith("http"):
                    findings.append({"tool": "httpx", "type": "live_host", "value": line.strip()})

        elif tool == "nmap":
            for line in lines:
                if "/tcp" in line or "/udp" in line:
                    findings.append({"tool": "nmap", "type": "open_port", "raw": line.strip()})

        elif tool in ("ffuf", "gobuster", "feroxbuster"):
            for line in lines:
                if "[Status:" in line or " 200 " in line or " 301 " in line:
                    findings.append({"tool": tool, "type": "endpoint", "raw": line.strip()})

        elif tool == "dalfox":
            for line in lines:
                if "[V]" in line or "XSS" in line.upper():
                    findings.append({"tool": "dalfox", "type": "xss",
                                     "severity": "HIGH", "raw": line.strip()})

        elif tool == "sqlmap":
            for line in lines:
                if "is vulnerable" in line.lower() or "injectable" in line.lower():
                    findings.append({"tool": "sqlmap", "type": "sqli",
                                     "severity": "CRITICAL", "raw": line.strip()})

        elif tool in ("trufflehog", "gitleaks"):
            for line in lines:
                if "Found" in line or "Leak" in line or "Secret" in line:
                    findings.append({"tool": tool, "type": "secret",
                                     "severity": "HIGH", "raw": line.strip()})

        elif tool == "arjun":
            for line in lines:
                if "[+]" in line:
                    findings.append({"tool": "arjun", "type": "parameter", "raw": line.strip()})

        elif tool == "gau":
            for line in lines:
                line = line.strip()
                if line.startswith("http"):
                    findings.append({"tool": "gau", "type": "historical_url", "value": line})

        else:
            for line in lines:
                if any(sig in line.upper() for sig in
                       ["VULN","CRITICAL","HIGH","INJECT","XSS","SQLI","RCE","SSRF"]):
                    findings.append({"tool": tool, "raw": line.strip()})

        return findings

    def _nuclei_severity(self, line: str) -> str:
        for sev in ["critical","high","medium","low","info"]:
            if f"[{sev}]" in line.lower():
                return sev.upper()
        return "INFO"


# ── Singleton ─────────────────────────────────────────────────

_instance = None

def get_kali_tools() -> KaliToolsMaximizer:
    global _instance
    if _instance is None:
        _instance = KaliToolsMaximizer()
    return _instance


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Kali tools status + auto-install")
    p.add_argument("--status",  action="store_true", help="Show tool status")
    p.add_argument("--install", action="store_true", help="Install missing critical tools")
    p.add_argument("--dry-run", action="store_true", help="Show what would be installed")
    args = p.parse_args()

    km = KaliToolsMaximizer()
    km.print_status()

    if args.install or args.dry_run:
        print("\nInstalling missing critical tools...")
        results = km.install_missing_critical(dry_run=args.dry_run)
        for name, status in results:
            print(f"  {name}: {status}")
