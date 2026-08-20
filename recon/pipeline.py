"""
AmonStrike — ProjectDiscovery Recon Pipeline
Stage 1: Full professional recon chain

Pipeline:
  subfinder → dnsx → httpx → katana → nuclei
  + gau + waybackurls + assetfinder
  + daily diff → alert on new attack surface

This is what top bug bounty hunters run 24/7.
Speed = finding bugs before everyone else.
"""

import os
import sys
import json
import time
import shutil
import hashlib
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; D = "\033[90m"; X = "\033[0m"

GOPATH_BIN = os.path.expanduser("~/go/bin")
TOOL_PATHS = {
    "subfinder":   shutil.which("subfinder")   or f"{GOPATH_BIN}/subfinder",
    "dnsx":        shutil.which("dnsx")        or f"{GOPATH_BIN}/dnsx",
    "httpx":       shutil.which("httpx")       or f"{GOPATH_BIN}/httpx",
    "katana":      shutil.which("katana")      or f"{GOPATH_BIN}/katana",
    "nuclei":      shutil.which("nuclei")      or f"{GOPATH_BIN}/nuclei",
    "naabu":       shutil.which("naabu")       or f"{GOPATH_BIN}/naabu",
    "gau":         shutil.which("gau")         or f"{GOPATH_BIN}/gau",
    "waybackurls": shutil.which("waybackurls") or f"{GOPATH_BIN}/waybackurls",
    "anew":        shutil.which("anew")        or f"{GOPATH_BIN}/anew",
    "assetfinder": shutil.which("assetfinder") or f"{GOPATH_BIN}/assetfinder",
    "qsreplace":   shutil.which("qsreplace")   or f"{GOPATH_BIN}/qsreplace",
    "unfurl":      shutil.which("unfurl")      or f"{GOPATH_BIN}/unfurl",
    "subzy":       shutil.which("subzy")       or f"{GOPATH_BIN}/subzy",
    "nmap":        shutil.which("nmap"),
    "ffuf":        shutil.which("ffuf"),
    "dalfox":      shutil.which("dalfox"),
    "sqlmap":      shutil.which("sqlmap"),
}


class ReconPipeline:
    """
    Full ProjectDiscovery recon pipeline.
    
    subfinder → dnsx → httpx → katana
    + gau + waybackurls
    + nuclei templates
    + daily diff + alert
    """

    def __init__(self, domain: str, output_dir: str,
                 rate_limit: int = 50, threads: int = 50,
                 silent: bool = False):
        self.domain     = domain.lstrip("*.").rstrip("/")
        self.output_dir = Path(output_dir)
        self.rate_limit = rate_limit
        self.threads    = threads
        self.silent     = silent
        self.timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir= self.output_dir / self.timestamp
        self.diff_dir   = self.output_dir / "latest"

        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.diff_dir.mkdir(parents=True, exist_ok=True)

        self.results = {
            "domain":      self.domain,
            "timestamp":   self.timestamp,
            "subdomains":  [],
            "live_hosts":  [],
            "urls":        [],
            "new_subs":    [],
            "new_hosts":   [],
            "new_urls":    [],
            "js_files":    [],
            "new_js":      [],
            "ports":       {},
            "nuclei_findings": [],
            "takeovers":   [],
            "secrets":     [],
        }

    def log(self, msg, level="+"):
        if self.silent:
            return
        colors = {"+": G, "!": R, "~": Y, "i": C, "*": D}
        c = colors.get(level, D)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {c}[RECON/{level}]{X} {msg}")

    def run(self) -> dict:
        """Run the full recon pipeline."""
        self.log(f"Starting full recon pipeline for: {self.domain}", "+")
        self.log(f"Output: {self.session_dir}", "i")

        # Step 1: Subdomain enumeration (parallel sources)
        self._step_subdomains()

        # Step 2: DNS resolution
        self._step_dns_resolve()

        # Step 3: HTTP probing
        self._step_http_probe()

        # Step 4: Port scanning (targeted)
        self._step_port_scan()

        # Step 5: URL discovery (gau + waybackurls + katana)
        self._step_url_discovery()

        # Step 6: JS file analysis
        self._step_js_analysis()

        # Step 7: Nuclei scanning
        self._step_nuclei_scan()

        # Step 8: Subdomain takeover check
        self._step_takeover_check()

        # Step 9: Diff vs previous scan
        self._step_diff()

        # Step 10: Save results
        self._save_results()

        self.log(
            f"Pipeline complete — "
            f"{len(self.results['subdomains'])} subs, "
            f"{len(self.results['live_hosts'])} live, "
            f"{len(self.results['urls'])} URLs, "
            f"{len(self.results['new_subs'])} NEW subs, "
            f"{len(self.results['nuclei_findings'])} nuclei findings",
            "+"
        )
        return self.results

    # ── Step 1: Subdomain Enumeration ────────────────────────

    def _step_subdomains(self):
        self.log("Step 1/10: Subdomain enumeration...", "*")
        all_subs = set()

        # Run all sources in parallel
        sources = {
            "subfinder":   self._subfinder,
            "assetfinder": self._assetfinder,
            "crtsh":       self._crtsh,
        }

        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(fn): name for name, fn in sources.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    subs = future.result()
                    all_subs.update(subs)
                    self.log(f"  {name}: {len(subs)} subdomains", "+")
                except Exception as e:
                    self.log(f"  {name}: {e}", "~")

        # Save
        subs_file = self.session_dir / "subdomains_raw.txt"
        subs_file.write_text("\n".join(sorted(all_subs)))
        self.results["subdomains"] = sorted(all_subs)
        self.log(f"Total unique subdomains: {len(all_subs)}", "+")

    def _subfinder(self) -> set:
        if not os.path.exists(TOOL_PATHS["subfinder"]):
            return set()
        out = self._run([
            TOOL_PATHS["subfinder"],
            "-d", self.domain,
            "-silent",
            "-t", "50",
            "-all",
        ], timeout=120)
        return {l.strip() for l in out.splitlines() if l.strip() and "." in l}

    def _assetfinder(self) -> set:
        if not os.path.exists(TOOL_PATHS.get("assetfinder","~")):
            return set()
        out = self._run([
            TOOL_PATHS["assetfinder"],
            "--subs-only",
            self.domain,
        ], timeout=60)
        return {l.strip() for l in out.splitlines()
                if l.strip() and self.domain in l}

    def _crtsh(self) -> set:
        try:
            import requests
            r = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=15
            )
            if r.status_code != 200:
                return set()
            subs = set()
            for entry in r.json():
                for name in entry.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(self.domain):
                        subs.add(name.lower())
            return subs
        except Exception:
            return set()

    # ── Step 2: DNS Resolution ────────────────────────────────

    def _step_dns_resolve(self):
        self.log("Step 2/10: DNS resolution...", "*")
        subs_file = self.session_dir / "subdomains_raw.txt"
        if not subs_file.exists() or subs_file.stat().st_size == 0:
            return

        live_file = self.session_dir / "subdomains_live.txt"

        if os.path.exists(TOOL_PATHS["dnsx"]):
            out = self._run([
                TOOL_PATHS["dnsx"],
                "-l", str(subs_file),
                "-silent",
                "-a", "-resp",
                "-t", "100",
            ], timeout=120)
            live_subs = set()
            for line in out.splitlines():
                if "[" in line:
                    sub = line.split("[")[0].strip()
                    live_subs.add(sub)
            live_file.write_text("\n".join(sorted(live_subs)))
            self.results["subdomains"] = sorted(live_subs)
            self.log(f"DNS resolved: {len(live_subs)} live subdomains", "+")
        else:
            # Fallback: socket resolution
            import socket
            live_subs = []
            for sub in self.results["subdomains"]:
                try:
                    socket.gethostbyname(sub)
                    live_subs.append(sub)
                except Exception:
                    pass
            live_file.write_text("\n".join(live_subs))
            self.results["subdomains"] = live_subs
            self.log(f"Socket resolved: {len(live_subs)} live subdomains", "+")

    # ── Step 3: HTTP Probing ──────────────────────────────────

    def _step_http_probe(self):
        self.log("Step 3/10: HTTP probing...", "*")
        subs_file = self.session_dir / "subdomains_live.txt"
        if not subs_file.exists() or subs_file.stat().st_size == 0:
            return

        hosts_file = self.session_dir / "live_hosts.txt"
        hosts_json = self.session_dir / "live_hosts.json"

        if os.path.exists(TOOL_PATHS["httpx"]):
            out = self._run([
                TOOL_PATHS["httpx"],
                "-l", str(subs_file),
                "-silent",
                "-title",
                "-status-code",
                "-tech-detect",
                "-follow-redirects",
                "-threads", "50",
                "-rate-limit", str(self.rate_limit),
                "-json",
                "-o", str(hosts_json),
            ], timeout=180)

            live_hosts = []
            if hosts_json.exists():
                for line in hosts_json.read_text().splitlines():
                    try:
                        data = json.loads(line)
                        live_hosts.append({
                            "url":    data.get("url",""),
                            "status": data.get("status-code", 0),
                            "title":  data.get("title",""),
                            "tech":   data.get("tech",[]),
                        })
                    except Exception:
                        pass

            hosts_file.write_text("\n".join([h["url"] for h in live_hosts]))
            self.results["live_hosts"] = live_hosts
            self.log(f"HTTP probe: {len(live_hosts)} live web services", "+")
        else:
            # Fallback: requests probe
            import requests
            live = []
            for sub in self.results["subdomains"][:100]:
                for scheme in ["https", "http"]:
                    try:
                        r = requests.get(
                            f"{scheme}://{sub}", timeout=5,
                            allow_redirects=True, verify=False
                        )
                        live.append({
                            "url":    r.url,
                            "status": r.status_code,
                            "title":  "",
                            "tech":   [],
                        })
                        break
                    except Exception:
                        pass
            hosts_file.write_text("\n".join([h["url"] for h in live]))
            self.results["live_hosts"] = live
            self.log(f"Requests probe: {len(live)} live hosts", "+")

    # ── Step 4: Port Scanning ─────────────────────────────────

    def _step_port_scan(self):
        self.log("Step 4/10: Port scanning (critical ports)...", "*")
        subs_file = self.session_dir / "subdomains_live.txt"
        if not subs_file.exists():
            return

        # Focus on high-value non-standard ports
        interesting_ports = "80,443,8080,8443,8888,3000,5000,4443,9090,9200,6379,27017,5432,3306"
        ports_file = self.session_dir / "open_ports.txt"

        if os.path.exists(TOOL_PATHS.get("naabu","")):
            out = self._run([
                TOOL_PATHS["naabu"],
                "-l", str(subs_file),
                "-p", interesting_ports,
                "-silent",
                "-rate", "1000",
            ], timeout=120)
            ports_file.write_text(out)
            for line in out.splitlines():
                if ":" in line:
                    host, port = line.rsplit(":", 1)
                    if host not in self.results["ports"]:
                        self.results["ports"][host] = []
                    self.results["ports"][host].append(port.strip())
            self.log(
                f"Port scan: {sum(len(v) for v in self.results['ports'].values())} open ports found",
                "+"
            )
        elif shutil.which("nmap"):
            # Fallback: nmap
            subs = (subs_file.read_text().strip().splitlines() or [self.domain])[:20]
            for sub in subs:
                out = self._run([
                    "nmap", "-p", interesting_ports,
                    "--open", "-T4", "-n", sub
                ], timeout=60)
                # Parse basic nmap output
                for line in out.splitlines():
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        if sub not in self.results["ports"]:
                            self.results["ports"][sub] = []
                        self.results["ports"][sub].append(port)

    # ── Step 5: URL Discovery ─────────────────────────────────

    def _step_url_discovery(self):
        self.log("Step 5/10: URL discovery (gau + waybackurls + katana)...", "*")
        hosts_file = self.session_dir / "live_hosts.txt"
        urls_file  = self.session_dir / "urls_all.txt"
        all_urls   = set()

        # gau (GetAllURLs)
        if os.path.exists(TOOL_PATHS.get("gau","")):
            out = self._run([
                TOOL_PATHS["gau"],
                "--subs",
                "--threads", "5",
                "--timeout", "30",
                self.domain,
            ], timeout=120)
            gau_urls = {l.strip() for l in out.splitlines() if l.strip()}
            all_urls.update(gau_urls)
            self.log(f"  gau: {len(gau_urls)} URLs", "+")

        # waybackurls
        if os.path.exists(TOOL_PATHS.get("waybackurls","")):
            out = self._run(
                [TOOL_PATHS["waybackurls"], self.domain],
                timeout=60
            )
            wb_urls = {l.strip() for l in out.splitlines() if l.strip()}
            all_urls.update(wb_urls)
            self.log(f"  waybackurls: {len(wb_urls)} URLs", "+")

        # katana (JS-aware crawler)
        if os.path.exists(TOOL_PATHS.get("katana","")) and hosts_file.exists():
            out = self._run([
                TOOL_PATHS["katana"],
                "-list", str(hosts_file),
                "-silent",
                "-jc",          # JS crawl
                "-kf", "all",   # Known files
                "-d", "3",      # Depth
                "-c", "20",     # Concurrency
                "-rl", str(self.rate_limit),
                "-timeout", "10",
            ], timeout=180)
            katana_urls = {l.strip() for l in out.splitlines() if l.strip()}
            all_urls.update(katana_urls)
            self.log(f"  katana: {len(katana_urls)} URLs", "+")

        # Filter and save
        filtered = self._filter_urls(all_urls)
        urls_file.write_text("\n".join(sorted(filtered)))
        self.results["urls"] = sorted(filtered)
        self.log(f"Total unique URLs: {len(filtered)}", "+")

    def _filter_urls(self, urls: set) -> set:
        """Filter URLs to keep interesting ones."""
        skip_ext = {".png",".jpg",".jpeg",".gif",".svg",".ico",
                    ".woff",".woff2",".ttf",".eot",".css",".map"}
        interesting = set()
        for url in urls:
            if not url.startswith("http"):
                continue
            ext = os.path.splitext(url.split("?")[0])[-1].lower()
            if ext in skip_ext:
                continue
            if self.domain not in url:
                continue
            interesting.add(url)
        return interesting

    # ── Step 6: JS Analysis ───────────────────────────────────

    def _step_js_analysis(self):
        self.log("Step 6/10: JS file analysis...", "*")
        urls = self.results.get("urls", [])

        # Find JS files
        js_urls = [u for u in urls if ".js" in u.lower()
                   and "?" not in u or u.endswith(".js")]
        self.results["js_files"] = js_urls

        if not js_urls:
            self.log("No JS files found", "~")
            return

        self.log(f"Analyzing {len(js_urls)} JS files for secrets...", "*")

        import re, requests
        # Secret patterns
        patterns = {
            "AWS_KEY":      r"AKIA[0-9A-Z]{16}",
            "AWS_SECRET":   r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]",
            "API_KEY":      r"(?i)(api_key|apikey|api-key)['\"\s:=]+([A-Za-z0-9_\-]{20,})",
            "SECRET_KEY":   r"(?i)(secret_key|secret)['\"\s:=]+([A-Za-z0-9_\-]{20,})",
            "PRIVATE_KEY":  r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "JWT_TOKEN":    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "GOOGLE_KEY":   r"AIza[0-9A-Za-z\-_]{35}",
            "SLACK_TOKEN":  r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-f]{32}",
            "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36,}",
            "INTERNAL_URL": r"https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost|127\.)[^\s\"']+",
            "ENDPOINT":     r"['\"`](/api/[a-zA-Z0-9/_-]+)['\"`]",
        }

        secrets_found = []
        js_dir = self.session_dir / "js_analysis"
        js_dir.mkdir(exist_ok=True)

        for js_url in js_urls[:50]:  # Limit for speed
            try:
                r = requests.get(js_url, timeout=10, verify=False)
                if r.status_code != 200:
                    continue
                content = r.text

                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    for match in matches[:3]:
                        finding = {
                            "type":  pattern_name,
                            "url":   js_url,
                            "match": str(match)[:100],
                        }
                        secrets_found.append(finding)
                        self.log(
                            f"  SECRET [{pattern_name}] in {js_url[:60]}",
                            "!"
                        )

            except Exception:
                pass

        self.results["secrets"] = secrets_found
        if secrets_found:
            secrets_file = self.session_dir / "secrets.json"
            secrets_file.write_text(json.dumps(secrets_found, indent=2))
            self.log(f"Secrets found: {len(secrets_found)}", "!")
        else:
            self.log("No secrets found in JS files", "~")

    # ── Step 7: Nuclei Scan ───────────────────────────────────

    def _step_nuclei_scan(self):
        self.log("Step 7/10: Nuclei vulnerability scan...", "*")
        hosts_file = self.session_dir / "live_hosts.txt"
        if not hosts_file.exists() or hosts_file.stat().st_size == 0:
            return

        nuclei_out = self.session_dir / "nuclei_findings.json"

        if not os.path.exists(TOOL_PATHS.get("nuclei","")):
            self.log("Nuclei not available", "~")
            return

        # Update templates first
        self._run([
            TOOL_PATHS["nuclei"],
            "-update-templates",
            "-silent",
        ], timeout=120)

        # Run nuclei with high-signal tags
        cmd = [
            TOOL_PATHS["nuclei"],
            "-l", str(hosts_file),
            "-t", os.path.expanduser("~/nuclei-templates/"),
            "-tags", "cve,misconfig,exposure,takeover,token,auth,xss,sqli,ssrf,lfi,rce,idor",
            "-severity", "low,medium,high,critical",
            "-rate-limit", str(self.rate_limit),
            "-bulk-size", "25",
            "-c", "25",
            "-timeout", "10",
            "-silent",
            "-json",
            "-o", str(nuclei_out),
            "-retries", "2",
            "-no-interactsh",  # Disable for now, add later
        ]

        self._run(cmd, timeout=600)

        findings = []
        if nuclei_out.exists():
            for line in nuclei_out.read_text().splitlines():
                try:
                    f = json.loads(line)
                    findings.append({
                        "template_id": f.get("template-id",""),
                        "name":        f.get("info",{}).get("name",""),
                        "severity":    f.get("info",{}).get("severity","").upper(),
                        "url":         f.get("matched-at",""),
                        "description": f.get("info",{}).get("description",""),
                        "reference":   f.get("info",{}).get("reference",[]),
                        "matcher":     f.get("matcher-name",""),
                        "extracted":   f.get("extracted-results",[]),
                        "curl":        f.get("curl-command",""),
                    })
                except Exception:
                    pass

        self.results["nuclei_findings"] = findings
        self.log(f"Nuclei: {len(findings)} findings", "+" if findings else "*")

    # ── Step 8: Takeover Check ────────────────────────────────

    def _step_takeover_check(self):
        self.log("Step 8/10: Subdomain takeover check...", "*")
        subs_file = self.session_dir / "subdomains_live.txt"
        if not subs_file.exists():
            return

        takeovers = []

        # Use nuclei takeover templates
        if os.path.exists(TOOL_PATHS.get("nuclei","")):
            out_file = self.session_dir / "takeover_nuclei.json"
            self._run([
                TOOL_PATHS["nuclei"],
                "-l", str(subs_file),
                "-t", os.path.expanduser("~/nuclei-templates/http/takeovers/"),
                "-severity", "high,critical",
                "-silent",
                "-json",
                "-o", str(out_file),
            ], timeout=180)

            if out_file.exists():
                for line in out_file.read_text().splitlines():
                    try:
                        f = json.loads(line)
                        takeovers.append({
                            "subdomain": f.get("matched-at",""),
                            "service":   f.get("template-id",""),
                            "severity":  "HIGH",
                        })
                        self.log(
                            f"TAKEOVER: {f.get('matched-at','')} ({f.get('template-id','')})",
                            "!"
                        )
                    except Exception:
                        pass

        # Also run subzy if available
        if os.path.exists(TOOL_PATHS.get("subzy","")):
            out = self._run([
                TOOL_PATHS["subzy"],
                "run",
                "--targets", str(subs_file),
                "--hide-fails",
            ], timeout=120)
            for line in out.splitlines():
                if "VULNERABLE" in line.upper():
                    takeovers.append({"subdomain": line.strip(), "service": "unknown", "severity": "HIGH"})
                    self.log(f"TAKEOVER (subzy): {line.strip()}", "!")

        self.results["takeovers"] = takeovers
        if takeovers:
            self.log(f"Takeovers found: {len(takeovers)} — SUBMIT IMMEDIATELY", "!")

    # ── Step 9: Diff vs Previous Scan ────────────────────────

    def _step_diff(self):
        self.log("Step 9/10: Diffing vs previous scan...", "*")

        def load_prev(filename: str) -> set:
            prev_file = self.diff_dir / filename
            if prev_file.exists():
                return set(prev_file.read_text().splitlines())
            return set()

        def save_latest(filename: str, data: list):
            (self.diff_dir / filename).write_text("\n".join(sorted(data)))

        # Subdomains diff
        prev_subs  = load_prev("subdomains.txt")
        curr_subs  = set(self.results["subdomains"])
        new_subs   = curr_subs - prev_subs
        self.results["new_subs"] = sorted(new_subs)
        save_latest("subdomains.txt", list(curr_subs))

        # Live hosts diff
        prev_hosts = load_prev("hosts.txt")
        curr_hosts = set(h["url"] for h in self.results["live_hosts"])
        new_hosts  = curr_hosts - prev_hosts
        self.results["new_hosts"] = sorted(new_hosts)
        save_latest("hosts.txt", list(curr_hosts))

        # URLs diff
        prev_urls  = load_prev("urls.txt")
        curr_urls  = set(self.results["urls"])
        new_urls   = curr_urls - prev_urls
        self.results["new_urls"] = sorted(new_urls)
        save_latest("urls.txt", list(curr_urls))

        # JS files diff
        prev_js    = load_prev("js_files.txt")
        curr_js    = set(self.results["js_files"])
        new_js     = curr_js - prev_js
        self.results["new_js"] = sorted(new_js)
        save_latest("js_files.txt", list(curr_js))

        # Report
        if new_subs or new_hosts or new_js:
            self.log(
                f"DELTA: +{len(new_subs)} subs, "
                f"+{len(new_hosts)} hosts, "
                f"+{len(new_js)} JS files",
                "!"
            )
            if new_js:
                self.log(
                    f"NEW JS FILES — test immediately: "
                    f"{list(new_js)[:3]}",
                    "!"
                )
        else:
            self.log("No new attack surface detected", "~")

    # ── Step 10: Save Results ─────────────────────────────────

    def _save_results(self):
        self.log("Step 10/10: Saving results...", "*")
        results_file = self.session_dir / "recon_results.json"
        results_file.write_text(json.dumps(self.results, indent=2))

        # Summary report
        summary = self.session_dir / "SUMMARY.txt"
        summary.write_text(self._build_summary())
        self.log(f"Results saved to: {self.session_dir}", "+")

    def _build_summary(self) -> str:
        r = self.results
        lines = [
            "═" * 60,
            f"AmonStrike Recon Summary — {self.domain}",
            f"Timestamp: {self.timestamp}",
            "═" * 60,
            f"Subdomains:      {len(r['subdomains'])} ({len(r['new_subs'])} NEW)",
            f"Live Hosts:      {len(r['live_hosts'])} ({len(r['new_hosts'])} NEW)",
            f"URLs:            {len(r['urls'])} ({len(r['new_urls'])} NEW)",
            f"JS Files:        {len(r['js_files'])} ({len(r['new_js'])} NEW)",
            f"Secrets Found:   {len(r['secrets'])}",
            f"Nuclei Findings: {len(r['nuclei_findings'])}",
            f"Takeovers:       {len(r['takeovers'])}",
            "═" * 60,
        ]
        if r["new_subs"]:
            lines.append("\nNEW SUBDOMAINS (test immediately):")
            lines.extend(f"  {s}" for s in r["new_subs"][:20])
        if r["new_js"]:
            lines.append("\nNEW JS FILES (high priority):")
            lines.extend(f"  {s}" for s in r["new_js"][:10])
        if r["takeovers"]:
            lines.append("\nTAKEOVER OPPORTUNITIES:")
            lines.extend(f"  {t['subdomain']}" for t in r["takeovers"])
        if r["secrets"]:
            lines.append("\nSECRETS FOUND:")
            lines.extend(f"  [{s['type']}] {s['url'][:60]}" for s in r["secrets"][:10])
        if r["nuclei_findings"]:
            lines.append("\nNUCLEI FINDINGS:")
            for f in r["nuclei_findings"][:20]:
                lines.append(f"  [{f['severity']}] {f['name']} — {f['url'][:60]}")
        return "\n".join(lines)

    # ── Helpers ───────────────────────────────────────────────

    def _run(self, cmd: list, timeout: int = 60, stdin_data: str = None) -> str:
        """Run a subprocess and return stdout."""
        try:
            # Ensure binary exists
            if not os.path.exists(cmd[0]):
                return ""
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_data,
                env={**os.environ,
                     "PATH": f"{GOPATH_BIN}:{os.environ.get('PATH','')}",
                     "GOPATH": "/root/go"},
            )
            return result.stdout or ""
        except subprocess.TimeoutExpired:
            self.log(f"Timeout: {cmd[0]}", "~")
            return ""
        except Exception as e:
            self.log(f"Error running {cmd[0]}: {e}", "~")
            return ""


def run_regression_tests():
    import tempfile
    print("\n=== RECON PIPELINE REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()
    pipe = ReconPipeline("testphp.vulnweb.com", tmp, silent=True)

    tests = [
        ("Pipeline instantiates",
         lambda: isinstance(pipe, ReconPipeline)),
        ("Domain normalized",
         lambda: pipe.domain == "testphp.vulnweb.com"),
        ("Output dirs created",
         lambda: pipe.session_dir.exists() and pipe.diff_dir.exists()),
        ("crtsh returns set",
         lambda: isinstance(pipe._crtsh(), set)),
        ("Filter URLs removes images",
         lambda: ".png" not in str(pipe._filter_urls({"http://testphp.vulnweb.com/img.png"}))),
        ("Filter URLs keeps endpoints",
         lambda: len(pipe._filter_urls({"http://testphp.vulnweb.com/api/users"})) == 1),
        ("Tool paths configured",
         lambda: isinstance(TOOL_PATHS, dict) and len(TOOL_PATHS) >= 10),
        ("Summary builds",
         lambda: "AmonStrike Recon Summary" in pipe._build_summary()),
        ("Save results works",
         lambda: (pipe._save_results() or True) and
                 (pipe.session_dir / "recon_results.json").exists()),
        ("Run command works",
         lambda: isinstance(pipe._run(["echo","test"]), str)),
        ("Diff step runs",
         lambda: (pipe._step_diff() or True) and isinstance(pipe.results["new_subs"], list)),
        ("Results structure correct",
         lambda: all(k in pipe.results for k in
             ["domain","subdomains","live_hosts","urls","nuclei_findings","secrets"])),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        rp, rf = run_regression_tests()
        sys.exit(0 if rf == 0 else 1)

    if len(sys.argv) < 2:
        print(f"Usage: python3 recon/pipeline.py <domain> [output_dir]")
        sys.exit(1)

    domain = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else f"output/recon_{domain}"
    pipe   = ReconPipeline(domain, outdir)
    results= pipe.run()
    print(f"\n{results['domain']}: {len(results['nuclei_findings'])} findings")
