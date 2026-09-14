"""
AmonStrike — Burp Suite Integration
Routes all traffic through Burp Suite proxy.
Burp captures, replays, and extends AmonStrike findings.
"""
import os, json, time, subprocess, requests, urllib3
from pathlib import Path

urllib3.disable_warnings()

BURP_PROXY  = "http://127.0.0.1:8080"
BURP_API    = "http://127.0.0.1:1337/v0.1"  # Burp REST API
BURP_CERT   = Path.home() / ".amonstrike" / "burp_ca.der"


class BurpIntegration:
    """
    Routes AmonStrike through Burp Suite.
    Burp sees all traffic, can replay/extend attacks.
    """

    def __init__(self, proxy_host: str = "127.0.0.1",
                 proxy_port: int = 8080,
                 api_port: int = 1337):
        self.proxy     = f"http://{proxy_host}:{proxy_port}"
        self.api_base  = f"http://{proxy_host}:{api_port}/v0.1"
        self.proxies   = {"http": self.proxy, "https": self.proxy}
        self.available = self._check_burp()

    def _check_burp(self) -> bool:
        """Check if Burp Suite is running."""
        try:
            r = requests.get(f"{self.api_base}/", timeout=3,
                           proxies=self.proxies, verify=False)
            print("  [BURP] Burp Suite detected — routing traffic through proxy")
            return True
        except Exception:
            try:
                # Try just the proxy
                r = requests.get("http://burp/", timeout=3,
                                proxies=self.proxies, verify=False)
                print("  [BURP] Burp proxy active")
                return True
            except Exception:
                return False

    def build_session(self, cookies: dict = None,
                      headers: dict = None) -> requests.Session:
        """Build requests session routed through Burp."""
        s = requests.Session()
        s.proxies.update(self.proxies)
        s.verify  = False  # Burp intercepts TLS

        # Install Burp CA if available
        if BURP_CERT.exists():
            s.verify = str(BURP_CERT)

        s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64)"
        if headers:
            s.headers.update(headers)
        if cookies:
            s.cookies.update(cookies)
        return s

    def install_cert(self):
        """Download and install Burp CA certificate."""
        try:
            r = requests.get(f"{self.proxy}/cert",
                           proxies=self.proxies, verify=False, timeout=5)
            if r.status_code == 200:
                BURP_CERT.parent.mkdir(parents=True, exist_ok=True)
                BURP_CERT.write_bytes(r.content)
                print(f"  [BURP] CA cert saved: {BURP_CERT}")
                # Install system-wide
                subprocess.run([
                    "sudo", "cp", str(BURP_CERT),
                    "/usr/local/share/ca-certificates/burp.crt"
                ], capture_output=True)
                subprocess.run(["sudo", "update-ca-certificates"],
                             capture_output=True)
                return True
        except Exception as e:
            print(f"  [BURP] Cert install failed: {e}")
        return False

    def get_findings_from_burp(self) -> list:
        """Get vulnerabilities found by Burp Scanner."""
        findings = []
        try:
            r = requests.get(f"{self.api_base}/scanner/issues",
                           timeout=10, verify=False)
            if r.status_code == 200:
                for issue in r.json():
                    sev_map = {
                        "high":           "HIGH",
                        "medium":         "MEDIUM",
                        "low":            "LOW",
                        "information":    "INFO",
                    }
                    findings.append({
                        "title":       issue.get("issue_type", {}).get("name",""),
                        "severity":    sev_map.get(issue.get("severity","").lower(),"MEDIUM"),
                        "url":         issue.get("origin",""),
                        "description": issue.get("issue_type",{}).get("description",""),
                        "evidence":    str(issue.get("evidence","")),
                        "remediation": issue.get("issue_type",{}).get("remediation",""),
                        "source":      "burp_scanner",
                        "module":      "burp",
                    })
            print(f"  [BURP] {len(findings)} issues from Burp Scanner")
        except Exception:
            pass
        return findings

    def send_to_burp(self, url: str, method: str = "GET",
                     headers: dict = None, body: str = ""):
        """Send a request through Burp (appears in Proxy history)."""
        try:
            s = self.build_session(headers=headers)
            if method == "GET":
                return s.get(url, timeout=10)
            return s.post(url, data=body, timeout=10)
        except Exception:
            return None

    def send_to_repeater_cmd(self, url: str, headers: dict,
                              body: str = "") -> str:
        """Generate curl command that goes through Burp."""
        header_str = " ".join(f'-H "{k}: {v}"' for k,v in headers.items())
        return (f'curl -sk -x {self.proxy} '
               f'"{url}" {header_str} '
               f'{f"-d \'"+body+"\'" if body else ""}'
               f' --proxy-insecure')

    def start_active_scan(self, url: str) -> bool:
        """Start Burp active scan on a URL."""
        try:
            r = requests.post(f"{self.api_base}/scanner/scans/active",
                            json={"urls": [url]}, timeout=10, verify=False)
            if r.status_code == 201:
                print(f"  [BURP] Active scan started: {url}")
                return True
        except Exception:
            pass
        return False

    def wait_for_scan(self, timeout: int = 300) -> list:
        """Wait for Burp scan to complete, return findings."""
        print(f"  [BURP] Waiting for scan (max {timeout}s)...")
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(10)
            findings = self.get_findings_from_burp()
            if findings:
                return findings
        return self.get_findings_from_burp()

    @staticmethod
    def launch_burp():
        """Launch Burp Suite if installed."""
        burp_paths = [
            "/usr/bin/burpsuite",
            "/opt/BurpSuitePro/BurpSuitePro",
            "/opt/BurpSuiteCommunity/BurpSuiteCommunity",
            str(Path.home() / "BurpSuitePro/BurpSuitePro"),
        ]
        for path in burp_paths:
            if os.path.exists(path):
                subprocess.Popen([path], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                print(f"  [BURP] Launching {path}")
                time.sleep(5)
                return True

        print("""
  [BURP] Burp Suite not found. Install:
  1. Community: apt install burpsuite
  2. Pro: download from portswigger.net
  3. Start manually, then run AmonStrike

  Quick setup:
    sudo apt install burpsuite -y
    burpsuite &
    # In Burp: Proxy → Options → 127.0.0.1:8080
    # Then re-run AmonStrike
""")
        return False

    @staticmethod
    def setup_instructions():
        print("""
╔══════════════════════════════════════════════════════╗
║  Burp Suite + AmonStrike Setup                       ║
╚══════════════════════════════════════════════════════╝

1. Install Burp Suite:
   sudo apt install burpsuite -y

2. Start Burp:
   burpsuite &
   # Proxy → Options → 127.0.0.1:8080

3. Install Burp CA cert:
   python3 core/burp_integration.py install-cert

4. Run AmonStrike through Burp:
   sudo python3 run.py https://target.com --burp

5. In Burp you will see:
   - All AmonStrike requests in Proxy history
   - Can replay/modify any request in Repeater
   - Active Scanner runs alongside AmonStrike
   - All findings in one place
""")
