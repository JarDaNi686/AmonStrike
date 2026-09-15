#!/usr/bin/env python3
"""
AmonStrike — Autonomous Tool Orchestrator
One URL in. Every tool runs. No human needed.

Parallel execution:
  - Burp Suite (auto-start, project create, scan, export)
  - SQLMap (deep SQL injection)
  - Nuclei (12,000+ templates)
  - Subfinder + HTTPx (recon)
  - Dalfox (XSS confirmation)
  - Nikto (web server scan)
  - FFuf (directory fuzzing)
  - Gobuster (endpoint discovery)
  - Katana (JS crawler)
  - WhatWeb (tech fingerprint)
  - AmonStrike modules (51 custom)

All results merged. Brain decides what's real.
"""

import os, sys, json, time, shutil, subprocess
import threading, queue, tempfile, hashlib
import requests, urllib3
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

urllib3.disable_warnings()

RESULTS_DIR = Path("output/orchestrator")
BURP_API    = "http://127.0.0.1:1337/v0.1"
BURP_PROXY  = "http://127.0.0.1:8080"


# ── Tool availability check ───────────────────────────────────

def check_tool(name: str) -> str:
    """Return path if tool available, else empty."""
    path = shutil.which(name)
    return path or ""


def check_and_report_tools():
    """Show which tools are available and how to install missing ones."""
    available   = {k:v for k,v in TOOLS.items() if v}
    unavailable = {k:v for k,v in TOOLS.items() if not v}
    print(f"  Available ({len(available)}): {', '.join(available.keys())}")
    if unavailable:
        print(f"  Missing  ({len(unavailable)}): {', '.join(unavailable.keys())}")
        print(f"  Install: sudo apt install -y {' '.join(k for k in unavailable if k in ['sqlmap','nikto','gobuster','nmap','burpsuite'])}")
        go_tools = [k for k in unavailable if k in ['nuclei','subfinder','httpx','dalfox','katana']]
        if go_tools:
            for t in go_tools:
                urls = {'nuclei':'projectdiscovery/nuclei/v3/cmd/nuclei',
                       'subfinder':'projectdiscovery/subfinder/v2/cmd/subfinder',
                       'httpx':'projectdiscovery/httpx/cmd/httpx',
                       'dalfox':'hahwul/dalfox/v2',
                       'katana':'projectdiscovery/katana/cmd/katana'}
                if t in urls:
                    print(f"  go install github.com/{urls[t]}@latest")

TOOLS = {
    "sqlmap":    check_tool("sqlmap"),
    "nuclei":    check_tool("nuclei"),
    "subfinder": check_tool("subfinder"),
    "httpx":     check_tool("httpx"),
    "dalfox":    check_tool("dalfox"),
    "nikto":     check_tool("nikto"),
    "ffuf":      check_tool("ffuf"),
    "gobuster":  check_tool("gobuster"),
    "katana":    check_tool("katana"),
    "whatweb":   check_tool("whatweb"),
    "nmap":      check_tool("nmap"),
    "burpsuite": check_tool("burpsuite"),
    "java":      check_tool("java"),
}


# ── Burp Suite Automation ─────────────────────────────────────

class BurpAutomation:
    """
    Fully automated Burp Suite.
    Starts → creates project → scans → returns findings.
    No human interaction needed.
    """

    def __init__(self, target: str, output_dir: Path,
                 proxy_port: int = 8080, api_port: int = 1337):
        self.target     = target
        self.output_dir = output_dir
        self.proxy_port = proxy_port
        self.api_port   = api_port
        self.api_base   = f"http://127.0.0.1:{api_port}/v0.1"
        self.proxies    = {"http": f"http://127.0.0.1:{proxy_port}",
                          "https": f"http://127.0.0.1:{proxy_port}"}
        self.process    = None
        self.findings   = []

    def start(self) -> bool:
        """Start Burp Suite headlessly."""
        if self._is_running():
            print("  [BURP] Already running")
            return True

        burp_paths = [
            "/usr/bin/burpsuite",
            "/usr/share/burpsuite/burpsuite.jar",
            str(Path.home() / "BurpSuitePro/burpsuite_pro.jar"),
            str(Path.home() / "tools/burpsuite_pro.jar"),
        ]

        jar_path = None
        for p in burp_paths:
            if os.path.exists(p):
                jar_path = p
                break

        if not jar_path:
            print("  [BURP] Not installed — install: sudo apt install burpsuite -y")
            return False

        # Generate Burp config for headless + REST API
        config = {
            "project_options": {
                "connections": {
                    "upstream_proxy": {"use_user_options": False},
                }
            },
            "user_options": {
                "proxy": {
                    "listeners": [{
                        "running": True,
                        "listener_port": self.proxy_port,
                        "listen_mode": "loopback_only",
                    }]
                },
                "misc": {
                    "api": {
                        "enabled": True,
                        "port": self.api_port,
                        "allow_public_api": True,
                        "require_api_key_auth": False,
                    }
                }
            }
        }

        config_file = self.output_dir / "burp_config.json"
        config_file.write_text(json.dumps(config))

        project_file = self.output_dir / "burp_project.burp"

        # Launch Burp headless
        cmd = [
            "java", "-jar", jar_path,
            "--headless.mode=true",
            f"--config-file={config_file}",
            f"--project-file={project_file}",
            "--unpause-spider-and-scanner",
        ] if jar_path.endswith(".jar") else [
            jar_path,
            "--headless.mode=true",
        ]

        print(f"  [BURP] Starting headless Burp Suite...")
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait for Burp to start
            for _ in range(30):
                time.sleep(2)
                if self._is_running():
                    print("  [BURP] Started successfully")
                    return True
        except Exception as e:
            print(f"  [BURP] Start failed: {e}")

        # Fallback: start normally (not headless)
        print("  [BURP] Trying GUI mode...")
        try:
            self.process = subprocess.Popen(
                ["burpsuite"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(8)
            return self._is_running()
        except Exception:
            return False

    def _is_running(self) -> bool:
        """Check if Burp is running and API accessible."""
        try:
            r = requests.get(f"{self.api_base}/",
                           timeout=3, verify=False)
            return r.status_code in [200, 404]
        except Exception:
            # Try proxy
            try:
                r = requests.get("http://burp/",
                               proxies=self.proxies,
                               timeout=3, verify=False)
                return True
            except Exception:
                return False

    def spider(self) -> bool:
        """Start Burp spider/crawler on target."""
        try:
            r = requests.post(
                f"{self.api_base}/spider/scans",
                json={"urls": [self.target]},
                timeout=10, verify=False,
            )
            if r.status_code in [200, 201]:
                print(f"  [BURP] Spider started: {self.target}")
                return True
        except Exception as e:
            print(f"  [BURP] Spider API error: {e}")
        return False

    def active_scan(self) -> str:
        """Start Burp active scanner, return scan ID."""
        try:
            r = requests.post(
                f"{self.api_base}/scanner/scans/active",
                json={
                    "urls":             [self.target],
                    "scan_configurations": [
                        {"name": "Audit coverage - maximum"},
                    ],
                },
                timeout=15, verify=False,
            )
            if r.status_code == 201:
                scan_id = r.headers.get("Location","").split("/")[-1]
                print(f"  [BURP] Active scan started: {scan_id}")
                return scan_id
        except Exception as e:
            print(f"  [BURP] Scan API error: {e}")
        return ""

    def wait_and_collect(self, scan_id: str = "",
                         timeout: int = 300) -> list:
        """Wait for scan to complete, collect findings."""
        print(f"  [BURP] Waiting for results (max {timeout}s)...")
        start = time.time()

        while time.time() - start < timeout:
            time.sleep(15)
            findings = self._get_issues()
            if findings:
                print(f"  [BURP] {len(findings)} issues found so far")

            # Check scan status
            if scan_id:
                try:
                    r = requests.get(
                        f"{self.api_base}/scanner/scans/{scan_id}",
                        timeout=10, verify=False,
                    )
                    if r.status_code == 200:
                        status = r.json().get("scan_status","")
                        if status in ["succeeded","failed"]:
                            break
                except Exception:
                    pass

        self.findings = self._get_issues()
        return self.findings

    def _get_issues(self) -> list:
        """Get all issues from Burp Scanner."""
        findings = []
        try:
            r = requests.get(
                f"{self.api_base}/scanner/issues",
                params={"origin": self.target},
                timeout=10, verify=False,
            )
            if r.status_code == 200:
                for issue in r.json():
                    sev = issue.get("severity","information").upper()
                    if sev == "INFORMATION": sev = "INFO"
                    findings.append({
                        "title":       issue.get("issue_type",{}).get("name",""),
                        "severity":    sev,
                        "url":         issue.get("origin",""),
                        "description": issue.get("issue_type",{}).get("description","")[:300],
                        "evidence":    str(issue.get("evidence",""))[:300],
                        "remediation": issue.get("issue_type",{}).get("remediation",""),
                        "source":      "burp",
                        "module":      "burp_scanner",
                        "timestamp":   datetime.now().isoformat(),
                    })
        except Exception:
            pass
        return findings

    def export_report(self) -> str:
        """Export Burp report to HTML."""
        try:
            r = requests.get(
                f"{self.api_base}/scanner/report",
                params={"reportType": "HTML"},
                timeout=30, verify=False,
            )
            if r.status_code == 200:
                out = self.output_dir / "burp_report.html"
                out.write_bytes(r.content)
                print(f"  [BURP] Report exported: {out}")
                return str(out)
        except Exception as e:
            print(f"  [BURP] Report export error: {e}")
        return ""

    def stop(self):
        """Stop Burp Suite."""
        if self.process:
            self.process.terminate()


# ── Parallel Tool Runner ──────────────────────────────────────

class ToolRunner:
    """Runs external security tools in parallel."""

    def __init__(self, target: str, output_dir: Path,
                 endpoints: list = None, cookies: dict = None,
                 h1_handle: str = "jardani101"):
        self.target     = target
        self.domain     = urlparse(target).netloc
        self.output_dir = output_dir
        self.endpoints  = endpoints or []
        self.cookies    = cookies or {}
        self.h1_handle  = h1_handle
        self.results    = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Build cookie string for tools
        self.cookie_str = "; ".join(f"{k}={v}" for k,v in self.cookies.items())
        self.header_str = f"X-HackerOne-Handle: {h1_handle}"

    def run_all(self) -> list:
        """Run all available tools in parallel."""
        tasks = []

        if TOOLS["subfinder"]:
            tasks.append(("subfinder", self._run_subfinder))
        if TOOLS["nuclei"]:
            tasks.append(("nuclei",    self._run_nuclei))
        if TOOLS["sqlmap"] and self.endpoints:
            tasks.append(("sqlmap",    self._run_sqlmap))
        if TOOLS["dalfox"] and self.endpoints:
            tasks.append(("dalfox",    self._run_dalfox))
        if TOOLS["nikto"]:
            tasks.append(("nikto",     self._run_nikto))
        if TOOLS["ffuf"]:
            tasks.append(("ffuf",      self._run_ffuf))
        if TOOLS["gobuster"]:
            tasks.append(("gobuster",  self._run_gobuster))
        if TOOLS["katana"]:
            tasks.append(("katana",    self._run_katana))
        if TOOLS["whatweb"]:
            tasks.append(("whatweb",   self._run_whatweb))
        if TOOLS["nmap"]:
            tasks.append(("nmap",      self._run_nmap))

        print(f"\n  [TOOLS] Running {len(tasks)} tools in parallel:")
        for name, _ in tasks:
            print(f"    - {name}")

        # Run all in parallel threads
        result_queue = queue.Queue()
        threads      = []

        def run_tool(name, fn):
            try:
                findings = fn()
                result_queue.put((name, findings))
                print(f"  [{name.upper()}] Complete — {len(findings)} findings")
            except Exception as e:
                result_queue.put((name, []))

        for name, fn in tasks:
            t = threading.Thread(target=run_tool, args=(name, fn), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=300)

        # Collect results
        while not result_queue.empty():
            name, findings = result_queue.get()
            self.results.extend(findings)

        print(f"\n  [TOOLS] Total: {len(self.results)} findings from external tools")
        return self.results

    def _run_subfinder(self) -> list:
        out_file = self.output_dir / "subfinder.txt"
        cmd = [TOOLS["subfinder"], "-d", self.domain,
               "-silent", "-timeout", "30", "-o", str(out_file)]
        subprocess.run(cmd, capture_output=True, timeout=120)
        if out_file.exists():
            subs = out_file.read_text().strip().splitlines()
            return [{
                "title":    f"Subdomain: {sub}",
                "severity": "INFO",
                "url":      f"https://{sub}",
                "source":   "subfinder",
                "module":   "recon",
                "description": f"Subdomain discovered: {sub}",
                "evidence": sub,
            } for sub in subs if sub]
        return []

    def _run_nuclei(self) -> list:
        out_file = self.output_dir / "nuclei.json"
        cmd = [
            TOOLS["nuclei"], "-u", self.target,
            "-silent", "-json", "-o", str(out_file),
            "-severity", "critical,high,medium",
            "-rate-limit", "10", "-timeout", "10",
            "-H", self.header_str,
        ]
        if self.cookie_str:
            cmd.extend(["-H", f"Cookie: {self.cookie_str}"])
        subprocess.run(cmd, capture_output=True, timeout=240)

        findings = []
        if out_file.exists():
            for line in out_file.read_text().strip().splitlines():
                try:
                    n = json.loads(line)
                    findings.append({
                        "title":       n.get("info",{}).get("name",""),
                        "severity":    n.get("info",{}).get("severity","MEDIUM").upper(),
                        "url":         n.get("matched-at",""),
                        "description": n.get("info",{}).get("description",""),
                        "evidence":    f"Template: {n.get('template-id','')}",
                        "cve":         ",".join(n.get("info",{}).get("classification",{}).get("cve-id",[])),
                        "source":      "nuclei",
                        "module":      "nuclei",
                        "timestamp":   datetime.now().isoformat(),
                    })
                except Exception:
                    pass
        return findings

    def _run_sqlmap(self) -> list:
        findings = []
        # Test injectable endpoints
        injectable = [ep for ep in self.endpoints[:5] if "?" in ep]
        for ep in injectable:
            out_file = self.output_dir / f"sqlmap_{hashlib.md5(ep.encode()).hexdigest()[:8]}.txt"
            cmd = [
                TOOLS["sqlmap"], "-u", ep,
                "--level=3", "--risk=2",
                "--batch", "--random-agent",
                "--output-dir", str(self.output_dir / "sqlmap"),
                "--headers", self.header_str,
            ]
            if self.cookie_str:
                cmd.extend(["--cookie", self.cookie_str])
            try:
                result = subprocess.run(cmd, capture_output=True,
                                       text=True, timeout=120)
                if "sqlmap identified the following injection point" in result.stdout:
                    findings.append({
                        "title":       f"SQLi Confirmed by SQLMap: {urlparse(ep).path}",
                        "severity":    "CRITICAL",
                        "url":         ep,
                        "description": "SQLMap confirmed SQL injection",
                        "evidence":    result.stdout[:500],
                        "source":      "sqlmap",
                        "module":      "sqli",
                        "timestamp":   datetime.now().isoformat(),
                    })
            except subprocess.TimeoutExpired:
                pass
        return findings

    def _run_dalfox(self) -> list:
        findings = []
        out_file = self.output_dir / "dalfox.json"
        # Test endpoints with params
        test_urls = [ep for ep in self.endpoints[:10] if "=" in ep]
        if not test_urls:
            test_urls = [self.target]

        for url in test_urls[:5]:
            cmd = [
                TOOLS["dalfox"], "url", url,
                "--silence", "--no-spinner",
                "--header", self.header_str,
                "--output", str(out_file),
                "--format", "json",
            ]
            if self.cookie_str:
                cmd.extend(["--cookie", self.cookie_str])
            try:
                subprocess.run(cmd, capture_output=True, timeout=60)
                if out_file.exists():
                    data = json.loads(out_file.read_text() or "[]")
                    for item in (data if isinstance(data, list) else [data]):
                        if item.get("type") in ["G", "R", "S"]:
                            findings.append({
                                "title":    f"XSS Confirmed by Dalfox: {urlparse(url).path}",
                                "severity": "HIGH",
                                "url":      item.get("data",""),
                                "description": "Dalfox confirmed XSS vulnerability",
                                "evidence": str(item),
                                "source":   "dalfox",
                                "module":   "xss",
                                "timestamp": datetime.now().isoformat(),
                            })
            except subprocess.TimeoutExpired:
                pass
        return findings

    def _run_nikto(self) -> list:
        out_file = self.output_dir / "nikto.json"
        cmd = [
            TOOLS["nikto"], "-h", self.target,
            "-Format", "json", "-output", str(out_file),
            "-nointeractive", "-timeout", "5",
            "-useragent", "Mozilla/5.0",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=180)
            if out_file.exists():
                data = json.loads(out_file.read_text() or "{}")
                findings = []
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "title":    vuln.get("msg","Nikto Finding"),
                        "severity": "MEDIUM",
                        "url":      self.target + vuln.get("url",""),
                        "description": vuln.get("msg",""),
                        "evidence": f"OSVDB: {vuln.get('osvdbid','')}",
                        "source":   "nikto",
                        "module":   "nikto",
                        "timestamp": datetime.now().isoformat(),
                    })
                return findings
        except subprocess.TimeoutExpired:
            pass
        return []

    def _run_ffuf(self) -> list:
        out_file = self.output_dir / "ffuf.json"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirb/big.txt"
        if not os.path.exists(wordlist):
            return []
        cmd = [
            TOOLS["ffuf"], "-u", f"{self.target}/FUZZ",
            "-w", wordlist,
            "-H", self.header_str,
            "-mc", "200,201,301,302,403",
            "-o", str(out_file), "-of", "json",
            "-t", "20", "-timeout", "5",
            "-s",  # silent
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=180)
            if out_file.exists():
                data = json.loads(out_file.read_text() or "{}")
                return [{
                    "title":    f"Directory Found: /{r.get('input',{}).get('FUZZ','')}",
                    "severity": "INFO",
                    "url":      r.get("url",""),
                    "description": f"HTTP {r.get('status','')} — {r.get('length',0)} bytes",
                    "evidence": f"Status: {r.get('status','')}",
                    "source":   "ffuf",
                    "module":   "dirs",
                    "timestamp": datetime.now().isoformat(),
                } for r in data.get("results",[])
                  if r.get("status",0) in [200,201]]
        except subprocess.TimeoutExpired:
            pass
        return []

    def _run_gobuster(self) -> list:
        out_file = self.output_dir / "gobuster.txt"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            return []
        cmd = [
            TOOLS["gobuster"], "dir",
            "-u", self.target,
            "-w", wordlist,
            "-H", self.header_str,
            "-x", "php,asp,aspx,jsp,json,txt,bak,sql,env,git",
            "-o", str(out_file),
            "-t", "20", "--timeout", "5s",
            "-q",  # quiet
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=180)
            if out_file.exists():
                findings = []
                for line in out_file.read_text().splitlines():
                    if "(Status: 200)" in line or "(Status: 301)" in line:
                        path = line.split(" ")[0]
                        findings.append({
                            "title":    f"Path Found: {path}",
                            "severity": "INFO",
                            "url":      self.target + path,
                            "description": line,
                            "evidence": line,
                            "source":   "gobuster",
                            "module":   "dirs",
                            "timestamp": datetime.now().isoformat(),
                        })
                return findings
        except subprocess.TimeoutExpired:
            pass
        return []

    def _run_katana(self) -> list:
        out_file = self.output_dir / "katana.txt"
        cmd = [
            TOOLS["katana"], "-u", self.target,
            "-d", "5", "-silent",
            "-H", self.header_str,
            "-o", str(out_file),
        ]
        if self.cookie_str:
            cmd.extend(["-H", f"Cookie: {self.cookie_str}"])
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            if out_file.exists():
                urls = out_file.read_text().strip().splitlines()
                return [{
                    "title":    f"Endpoint: {url}",
                    "severity": "INFO",
                    "url":      url,
                    "description": "Endpoint discovered by Katana crawler",
                    "evidence": url,
                    "source":   "katana",
                    "module":   "recon",
                    "timestamp": datetime.now().isoformat(),
                } for url in urls[:50] if url]
        except subprocess.TimeoutExpired:
            pass
        return []

    def _run_whatweb(self) -> list:
        cmd = [TOOLS["whatweb"], self.target, "--log-json=/tmp/whatweb.json",
               "-a", "3", "--quiet"]
        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
            data = json.loads(Path("/tmp/whatweb.json").read_text() or "[]")
            findings = []
            for entry in (data if isinstance(data, list) else [data]):
                for plugin, info in entry.get("plugins", {}).items():
                    if plugin in ["PHP","Apache","Nginx","jQuery","WordPress"]:
                        version = info.get("version", [""])[0] if info.get("version") else ""
                        findings.append({
                            "title":    f"Tech Detected: {plugin} {version}",
                            "severity": "INFO",
                            "url":      self.target,
                            "description": f"{plugin} {version} detected",
                            "evidence": str(info),
                            "source":   "whatweb",
                            "module":   "intelligence",
                            "timestamp": datetime.now().isoformat(),
                        })
            return findings
        except Exception:
            return []

    def _run_nmap(self) -> list:
        domain = urlparse(self.target).netloc
        out_file = self.output_dir / "nmap.xml"
        cmd = [
            TOOLS["nmap"], "-sV", "--script=http-title,http-headers",
            "-p", "80,443,8080,8443,8000,3000,5000",
            "-oX", str(out_file), "-T3", domain,
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            # Parse XML for open ports
            if out_file.exists():
                import xml.etree.ElementTree as ET
                tree = ET.parse(out_file)
                findings = []
                for port in tree.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        portid  = port.get("portid","")
                        service = port.find("service")
                        svc     = service.get("name","") if service is not None else ""
                        ver     = service.get("version","") if service is not None else ""
                        findings.append({
                            "title":    f"Open Port {portid}/{svc} {ver}",
                            "severity": "INFO",
                            "url":      self.target,
                            "description": f"Port {portid} open: {svc} {ver}",
                            "evidence": f"{domain}:{portid} {svc} {ver}",
                            "source":   "nmap",
                            "module":   "ports",
                            "timestamp": datetime.now().isoformat(),
                        })
                return findings
        except subprocess.TimeoutExpired:
            pass
        return []


# ── Master Orchestrator ───────────────────────────────────────

class MasterOrchestrator:
    """
    Coordinates everything. One URL in. Everything runs.
    Brain makes all decisions. No human needed.
    """

    def __init__(self, target: str, program: str = "",
                 h1_handle: str = "jardani101",
                 use_burp: bool = True):
        self.target    = target
        self.program   = program
        self.h1_handle = h1_handle
        self.use_burp  = use_burp
        self.domain    = urlparse(target).netloc
        self.output_dir= Path(f"output/{self.domain}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.all_findings = []

    def run(self) -> dict:
        print(f"""
{'='*60}
  AMONSTRIKE MASTER ORCHESTRATOR
  Target:  {self.target}
  Program: {self.program or 'none'}
  Tools:   {sum(1 for v in TOOLS.values() if v)} available
{'='*60}
""")
        # Print tool status
        for tool, path in TOOLS.items():
            status = "✓" if path else "✗"
            print(f"  [{status}] {tool}")

        print()

        # Phase 1: Get session
        print("[Phase 1] Getting session...")
        cookies = {}
        try:
            from core.session_manager import SessionManager
            sm      = SessionManager()
            cookies = sm.get(self.domain)
        except Exception:
            pass

        # Phase 2: Discover surface
        print("\n[Phase 2] Discovering attack surface...")
        endpoints = []
        try:
            import urllib3; urllib3.disable_warnings()
            import requests as req
            s = req.Session()
            s.verify = False
            s.headers.update({"User-Agent":"Mozilla/5.0",
                             "X-HackerOne-Handle": self.h1_handle})
            if cookies: s.cookies.update(cookies)
            from core.surface_discovery import AggressiveSurfaceDiscovery
            disc      = AggressiveSurfaceDiscovery(self.target, s,
                            {"X-HackerOne-Handle": self.h1_handle})
            surface   = disc.run()
            endpoints = surface.get("endpoints", [])
            print(f"  [+] {len(endpoints)} endpoints found")
        except Exception as e:
            print(f"  [!] Surface discovery: {e}")

        # Phase 3: Start Burp + external tools in parallel
        print("\n[Phase 3] Starting Burp Suite + all tools in parallel...")

        burp    = None
        scan_id = ""

        if self.use_burp:
            burp = BurpAutomation(self.target, self.output_dir)
            burp_started = burp.start()
            if burp_started:
                burp.spider()
                scan_id = burp.active_scan()

        # Run external tools in parallel
        tool_runner = ToolRunner(
            self.target, self.output_dir,
            endpoints, cookies, self.h1_handle
        )
        tool_findings = tool_runner.run_all()
        self.all_findings.extend(tool_findings)

        # Phase 4: AmonStrike modules
        print("\n[Phase 4] AmonStrike attack modules...")
        try:
            from core.pipeline import AmonStrikePipeline
            pipeline = AmonStrikePipeline(
                target         = self.target,
                output_dir     = str(self.output_dir),
                credentials    = [{"cookies": cookies}] if cookies else [],
                program_handle = self.program,
            )
            result   = pipeline.run()
            module_findings = result.get("findings", [])
            self.all_findings.extend(module_findings)
            print(f"  [+] {len(module_findings)} findings from modules")
        except Exception as e:
            print(f"  [!] Pipeline: {e}")

        # Phase 5: Collect Burp results
        if burp and burp.available:
            print("\n[Phase 5] Collecting Burp Scanner results...")
            burp_findings = burp.wait_and_collect(scan_id, timeout=180)
            self.all_findings.extend(burp_findings)
            burp.export_report()

        # Phase 6: Deduplicate + validate with brain
        print("\n[Phase 6] Brain validation + deduplication...")
        self.all_findings = self._dedup(self.all_findings)
        self.all_findings = self._validate_with_brain(self.all_findings)

        # Phase 7: Generate report
        print("\n[Phase 7] Generating H1 report...")
        self._generate_report()

        print(f"\n{'='*60}")
        print(f"  COMPLETE — {len(self.all_findings)} total findings")
        sev = {}
        for f in self.all_findings:
            s = f.get("severity","INFO")
            sev[s] = sev.get(s,0) + 1
        for s,c in sorted(sev.items()):
            if c: print(f"  {s}: {c}")
        print(f"\n  Reports: {self.output_dir}/")
        print(f"{'='*60}")

        return {"findings": self.all_findings, "output": str(self.output_dir)}

    def _dedup(self, findings: list) -> list:
        seen  = set()
        dedup = []
        for f in findings:
            sig = hashlib.md5(
                f"{f.get('title','')}|{f.get('url','')}".encode()
            ).hexdigest()
            if sig not in seen:
                seen.add(sig)
                dedup.append(f)
        removed = len(findings) - len(dedup)
        if removed:
            print(f"  [+] Removed {removed} duplicates")
        return dedup

    def _validate_with_brain(self, findings: list) -> list:
        """Use local brain to validate findings."""
        try:
            from core.local_brain import LocalBrain
            brain   = LocalBrain()
            valid   = []
            for f in findings:
                result = brain.validate_finding(f, f.get("evidence",""))
                if result.get("is_real", True):
                    f["confidence"]  = result.get("confidence", 50)
                    f["brain_notes"] = result.get("reasoning","")
                    valid.append(f)
                else:
                    print(f"  [BRAIN] Rejected: {f.get('title','')[:50]}")
            return valid
        except Exception:
            return findings

    def _generate_report(self):
        """Generate H1 submission portal."""
        reportable = [f for f in self.all_findings
                     if f.get("severity") in ["CRITICAL","HIGH","MEDIUM"]]
        if not reportable:
            return
        try:
            from reports.hackerone_format import generate_h1_package
            pkg = generate_h1_package(
                reportable, str(self.output_dir),
                program_handle=self.program,
                target_url=self.target,
            )
            if pkg.get("portal"):
                print(f"  [+] H1 Portal: {pkg['portal']}")
        except Exception as e:
            print(f"  [!] Report: {e}")


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="AmonStrike Master Orchestrator")
    p.add_argument("url",              help="Target URL")
    p.add_argument("program",  nargs="?", default="", help="H1 program handle")
    p.add_argument("--no-burp",action="store_true",  help="Skip Burp Suite")
    p.add_argument("--tools",  default="all",        help="Tools to run (comma-separated)")
    args = p.parse_args()

    orch = MasterOrchestrator(
        target    = args.url,
        program   = args.program,
        use_burp  = not args.no_burp,
    )
    orch.run()
