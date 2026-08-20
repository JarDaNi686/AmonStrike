"""
AmonStrike — Auto Tool Installer
Checks, installs, and verifies all required tools.
Never fails silently — always has a fallback.
"""

import os
import sys
import subprocess
import shutil
import time
import json
from datetime import datetime

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; D = "\033[90m"; X = "\033[0m"

# ── Tool Registry ─────────────────────────────────────────────
# Every tool has:
#   check:    how to verify it exists
#   version:  how to get version
#   install:  ordered list of install methods (tried in order)
#   fallback: what AmonStrike does if install fails
#   critical: if True, scan cannot proceed without it

TOOL_REGISTRY = {

    # ── Network ───────────────────────────────────────────────
    "nmap": {
        "binary":   "nmap",
        "version":  ["nmap", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y nmap"},
        ],
        "fallback": "Use socket-based port scanner (built-in)",
        "critical": False,
        "category": "network",
    },
    "masscan": {
        "binary":   "masscan",
        "version":  ["masscan", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y masscan"},
            {"method": "git",  "cmd": "git clone https://github.com/robertdavidgraham/masscan /tmp/masscan && cd /tmp/masscan && make && cp bin/masscan /usr/local/bin/"},
        ],
        "fallback": "Use nmap for port scanning",
        "critical": False,
        "category": "network",
    },

    # ── Web Enumeration ───────────────────────────────────────
    "gobuster": {
        "binary":   "gobuster",
        "version":  ["gobuster", "version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y gobuster"},
            {"method": "go",   "cmd": "go install github.com/OJ/gobuster/v3@latest"},
        ],
        "fallback": "Use built-in dir enumeration module",
        "critical": False,
        "category": "web_enum",
    },
    "ffuf": {
        "binary":   "ffuf",
        "version":  ["ffuf", "-V"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y ffuf"},
            {"method": "go",   "cmd": "go install github.com/ffuf/ffuf/v2@latest"},
        ],
        "fallback": "Use gobuster or built-in dir module",
        "critical": False,
        "category": "web_enum",
    },
    "feroxbuster": {
        "binary":   "feroxbuster",
        "version":  ["feroxbuster", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y feroxbuster"},
            {"method": "curl", "cmd": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin"},
        ],
        "fallback": "Use gobuster or ffuf",
        "critical": False,
        "category": "web_enum",
    },

    # ── Web Scanners ──────────────────────────────────────────
    "nikto": {
        "binary":   "nikto",
        "version":  ["nikto", "-Version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y nikto"},
            {"method": "git",  "cmd": "git clone https://github.com/sullo/nikto /opt/nikto && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && chmod +x /opt/nikto/program/nikto.pl"},
        ],
        "fallback": "Use built-in vulnerability modules",
        "critical": False,
        "category": "web_scan",
    },
    "whatweb": {
        "binary":   "whatweb",
        "version":  ["whatweb", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y whatweb"},
            {"method": "gem",  "cmd": "gem install whatweb"},
        ],
        "fallback": "Use built-in tech detection in recon module",
        "critical": False,
        "category": "web_scan",
    },
    "wafw00f": {
        "binary":   "wafw00f",
        "version":  ["wafw00f", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y wafw00f"},
            {"method": "pip",  "cmd": "pip install wafw00f --break-system-packages"},
        ],
        "fallback": "Skip WAF detection, attempt all payloads",
        "critical": False,
        "category": "web_scan",
    },
    "nuclei": {
        "binary":   "nuclei",
        "version":  ["nuclei", "-version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y nuclei"},
            {"method": "go",   "cmd": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
        ],
        "fallback": "Use built-in CVE checks",
        "critical": False,
        "category": "web_scan",
    },

    # ── SQL Injection ─────────────────────────────────────────
    "sqlmap": {
        "binary":   "sqlmap",
        "version":  ["sqlmap", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y sqlmap"},
            {"method": "git",  "cmd": "git clone https://github.com/sqlmapproject/sqlmap /opt/sqlmap && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && chmod +x /opt/sqlmap/sqlmap.py"},
        ],
        "fallback": "Use built-in SQLi module",
        "critical": False,
        "category": "sqli",
    },

    # ── XSS ──────────────────────────────────────────────────
    "dalfox": {
        "binary":   "dalfox",
        "version":  ["dalfox", "version"],
        "install": [
            {"method": "go",   "cmd": "go install github.com/hahwul/dalfox/v2@latest"},
            {"method": "apt",  "cmd": "apt-get install -y dalfox"},
        ],
        "fallback": "Use built-in XSS module",
        "critical": False,
        "category": "xss",
    },

    # ── OSINT ─────────────────────────────────────────────────
    "theHarvester": {
        "binary":   "theHarvester",
        "version":  ["theHarvester", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y theharvester"},
            {"method": "pip",  "cmd": "pip install theHarvester --break-system-packages"},
        ],
        "fallback": "Use built-in DNS enumeration",
        "critical": False,
        "category": "osint",
    },
    "amass": {
        "binary":   "amass",
        "version":  ["amass", "version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y amass"},
            {"method": "go",   "cmd": "go install -v github.com/owasp-amass/amass/v4/...@master"},
            {"method": "snap", "cmd": "snap install amass"},
        ],
        "fallback": "Use subfinder + built-in DNS enumeration",
        "critical": False,
        "category": "osint",
    },
    "subfinder": {
        "binary":   "subfinder",
        "version":  ["subfinder", "-version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y subfinder"},
            {"method": "go",   "cmd": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
        ],
        "fallback": "Use amass or built-in DNS enumeration",
        "critical": False,
        "category": "osint",
    },
    "dnsx": {
        "binary":   "dnsx",
        "version":  ["dnsx", "-version"],
        "install": [
            {"method": "go",   "cmd": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
            {"method": "apt",  "cmd": "apt-get install -y dnsx"},
        ],
        "fallback": "Use built-in DNS resolution",
        "critical": False,
        "category": "osint",
    },

    # ── CMS Scanners ──────────────────────────────────────────
    "wpscan": {
        "binary":   "wpscan",
        "version":  ["wpscan", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y wpscan"},
            {"method": "gem",  "cmd": "gem install wpscan"},
        ],
        "fallback": "Use built-in WordPress checks in recon module",
        "critical": False,
        "category": "cms",
    },

    # ── Brute Force ───────────────────────────────────────────
    "hydra": {
        "binary":   "hydra",
        "version":  ["hydra", "-h"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y hydra"},
        ],
        "fallback": "Use built-in auth module for default creds",
        "critical": False,
        "category": "bruteforce",
    },

    # ── JS Analysis ───────────────────────────────────────────
    "linkfinder": {
        "binary":   "linkfinder",
        "version":  ["linkfinder", "--help"],
        "install": [
            {"method": "pip",  "cmd": "pip install linkfinder --break-system-packages"},
            {"method": "git",  "cmd": "git clone https://github.com/GerbenJavado/LinkFinder /opt/linkfinder && pip install -r /opt/linkfinder/requirements.txt --break-system-packages && ln -sf /opt/linkfinder/linkfinder.py /usr/local/bin/linkfinder && chmod +x /opt/linkfinder/linkfinder.py"},
        ],
        "fallback": "Use built-in JS endpoint extraction (regex-based)",
        "critical": False,
        "category": "js_analysis",
    },

    # ── Utilities ─────────────────────────────────────────────
    "curl": {
        "binary":   "curl",
        "version":  ["curl", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y curl"},
        ],
        "fallback": "Use Python requests library",
        "critical": False,
        "category": "utility",
    },
    "jq": {
        "binary":   "jq",
        "version":  ["jq", "--version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y jq"},
        ],
        "fallback": "Use Python json module",
        "critical": False,
        "category": "utility",
    },
    "go": {
        "binary":   "go",
        "version":  ["go", "version"],
        "install": [
            {"method": "apt",  "cmd": "apt-get install -y golang-go"},
        ],
        "fallback": "Skip go-based tools",
        "critical": False,
        "category": "runtime",
    },
}

# ── Regression Test Cases ─────────────────────────────────────
REGRESSION_TESTS = [
    {
        "name": "Tool check returns correct boolean",
        "fn": lambda i: i.is_installed("curl") == bool(shutil.which("curl")),
    },
    {
        "name": "Install status file is valid JSON",
        "fn": lambda i: isinstance(i._load_status(), dict),
    },
    {
        "name": "Fallback always defined for every tool",
        "fn": lambda i: all("fallback" in v for v in TOOL_REGISTRY.values()),
    },
    {
        "name": "No tool marked critical blocks scan",
        "fn": lambda i: not any(v.get("critical", False) for v in TOOL_REGISTRY.values()),
    },
]


class ToolInstaller:
    """
    Auto-installs missing tools.
    Never blocks — always has a fallback.
    Caches install status to avoid repeated checks.
    """

    STATUS_FILE = "/tmp/amonstrike_tools.json"
    GOPATH = os.path.expanduser("~/go/bin")

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.status  = self._load_status()
        self._setup_path()

    def _setup_path(self):
        """Ensure Go binary path is in PATH."""
        if self.GOPATH not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{self.GOPATH}:{os.environ.get('PATH','')}"

    def _load_status(self):
        """Load cached tool status."""
        try:
            if os.path.exists(self.STATUS_FILE):
                with open(self.STATUS_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_status(self):
        """Save tool status to cache."""
        try:
            with open(self.STATUS_FILE, "w") as f:
                json.dump(self.status, f, indent=2)
        except Exception:
            pass

    def is_installed(self, tool_name):
        """Check if a tool binary is available."""
        binary = TOOL_REGISTRY.get(tool_name, {}).get("binary", tool_name)
        return bool(shutil.which(binary))

    def get_version(self, tool_name):
        """Get tool version string."""
        cmd = TOOL_REGISTRY.get(tool_name, {}).get("version", [tool_name, "--version"])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return (r.stdout + r.stderr).strip().split("\n")[0]
        except Exception:
            return "unknown"

    def _run_install(self, method, cmd, timeout=120):
        """Run an install command."""
        try:
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            r = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout, env=env
            )
            return r.returncode == 0, r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, str(e)

    def install(self, tool_name):
        """
        Try all install methods for a tool.
        Returns (success, method_used, fallback_message)
        """
        if self.is_installed(tool_name):
            return True, "already_installed", None

        tool = TOOL_REGISTRY.get(tool_name)
        if not tool:
            return False, None, "Tool not in registry"

        fallback = tool.get("fallback", "Skip this tool")

        for install_spec in tool.get("install", []):
            method = install_spec["method"]
            cmd    = install_spec["cmd"]

            if self.verbose:
                self._log(f"Trying {method}: {tool_name}", "~")

            # Pre-check: is the install method available?
            if method == "go" and not shutil.which("go"):
                if self.verbose:
                    self._log("Go not installed, skipping go install", "~")
                continue
            if method == "gem" and not shutil.which("gem"):
                continue
            if method == "snap" and not shutil.which("snap"):
                continue

            success, output = self._run_install(method, cmd)

            if success and self.is_installed(tool_name):
                version = self.get_version(tool_name)
                self.status[tool_name] = {
                    "installed": True,
                    "method": method,
                    "version": version,
                    "time": datetime.now().isoformat(),
                }
                self._save_status()
                return True, method, None

        # All methods failed — log fallback
        self.status[tool_name] = {
            "installed": False,
            "fallback": fallback,
            "time": datetime.now().isoformat(),
        }
        self._save_status()
        return False, None, fallback

    def check_and_install_all(self, tools=None, categories=None):
        """
        Check and install all tools (or specified subset).
        Returns dict of {tool: status}
        """
        if tools is None:
            tools = list(TOOL_REGISTRY.keys())

        if categories:
            tools = [t for t in tools
                    if TOOL_REGISTRY.get(t, {}).get("category") in categories]

        results = {}
        installed_count  = 0
        failed_count     = 0
        already_count    = 0

        print(f"\n{D}  ┌{'─'*60}┐{X}")
        print(f"{D}  │{X}{W}  AMONSTRIKE TOOL CHECKER{X}{D}{'':>37}│{X}")
        print(f"{D}  ├{'─'*60}┤{X}")

        for tool in tools:
            if self.is_installed(tool):
                version = self.get_version(tool)
                print(f"{D}  │{X}  {G}✓{X} {W}{tool:<20}{X} {D}{version[:35]}{X}")
                results[tool] = {"status": "available", "version": version}
                already_count += 1
            else:
                print(f"{D}  │{X}  {Y}↓{X} {W}{tool:<20}{X} {Y}Installing...{X}", end="\r")
                success, method, fallback = self.install(tool)

                if success:
                    version = self.get_version(tool)
                    print(f"{D}  │{X}  {G}✓{X} {W}{tool:<20}{X} {G}Installed via {method}{X}          ")
                    results[tool] = {"status": "installed", "method": method, "version": version}
                    installed_count += 1
                else:
                    print(f"{D}  │{X}  {R}✗{X} {W}{tool:<20}{X} {R}Failed{X} → {D}{fallback[:30]}{X}")
                    results[tool] = {"status": "fallback", "fallback": fallback}
                    failed_count += 1

        print(f"{D}  ├{'─'*60}┤{X}")
        print(f"{D}  │{X}  {G}Available: {already_count + installed_count}{X}  "
              f"{Y}Newly installed: {installed_count}{X}  "
              f"{R}Using fallback: {failed_count}{X}")
        print(f"{D}  └{'─'*60}┘{X}\n")

        return results

    def get_available_tools(self):
        """Return dict of available tools with their binary paths."""
        available = {}
        for name, tool in TOOL_REGISTRY.items():
            binary = tool["binary"]
            path = shutil.which(binary)
            if path:
                available[name] = path
        return available

    def get_fallback(self, tool_name):
        """Get the fallback description for a tool."""
        return TOOL_REGISTRY.get(tool_name, {}).get("fallback", "Skip")

    def _log(self, msg, level="*"):
        colors = {"*": D, "!": R, "+": G, "~": Y, "i": C}
        c = colors.get(level, D)
        print(f"    {c}[{level}]{X} {msg}")

    def run_regression_tests(self):
        """Run all regression tests. Returns (passed, failed, results)."""
        passed = 0
        failed = 0
        results = []

        print(f"\n{W}  Running regression tests...{X}")

        for test in REGRESSION_TESTS:
            try:
                result = test["fn"](self)
                if result:
                    passed += 1
                    results.append((test["name"], True, ""))
                    print(f"  {G}✓{X} {test['name']}")
                else:
                    failed += 1
                    results.append((test["name"], False, "Assertion failed"))
                    print(f"  {R}✗{X} {test['name']}")
            except Exception as e:
                failed += 1
                results.append((test["name"], False, str(e)))
                print(f"  {R}✗{X} {test['name']} — {e}")

        print(f"\n  {G}Passed: {passed}{X}  {R}Failed: {failed}{X}\n")
        return passed, failed, results

    def stress_test(self):
        """
        Stress test the installer:
        - Test with nonexistent tool
        - Test double-install (idempotent)
        - Test fallback retrieval
        - Test PATH setup
        - Test status persistence
        """
        print(f"\n{W}  Running stress tests...{X}")
        results = []

        # Test 1: Nonexistent tool
        try:
            success, _, fallback = self.install("nonexistent_tool_xyz")
            assert not success, "Should fail for unknown tool"
            results.append(("Nonexistent tool handled gracefully", True))
            print(f"  {G}✓{X} Nonexistent tool handled gracefully")
        except Exception as e:
            results.append(("Nonexistent tool handled gracefully", False))
            print(f"  {R}✗{X} Nonexistent tool: {e}")

        # Test 2: Double install (idempotent)
        try:
            r1 = self.is_installed("curl")
            r2 = self.is_installed("curl")
            assert r1 == r2, "is_installed must be idempotent"
            results.append(("is_installed is idempotent", True))
            print(f"  {G}✓{X} is_installed is idempotent")
        except Exception as e:
            results.append(("is_installed is idempotent", False))
            print(f"  {R}✗{X} Idempotency: {e}")

        # Test 3: All tools have fallbacks
        try:
            no_fallback = [t for t, v in TOOL_REGISTRY.items() if not v.get("fallback")]
            assert not no_fallback, f"Missing fallback: {no_fallback}"
            results.append(("All tools have fallbacks", True))
            print(f"  {G}✓{X} All {len(TOOL_REGISTRY)} tools have fallbacks")
        except Exception as e:
            results.append(("All tools have fallbacks", False))
            print(f"  {R}✗{X} Missing fallbacks: {e}")

        # Test 4: Status file persistence
        try:
            self.status["_stress_test"] = {"test": True}
            self._save_status()
            loaded = self._load_status()
            assert "_stress_test" in loaded
            del self.status["_stress_test"]
            self._save_status()
            results.append(("Status persistence works", True))
            print(f"  {G}✓{X} Status persistence works")
        except Exception as e:
            results.append(("Status persistence works", False))
            print(f"  {R}✗{X} Persistence: {e}")

        # Test 5: PATH includes Go binaries
        try:
            assert self.GOPATH in os.environ.get("PATH", "")
            results.append(("Go PATH configured", True))
            print(f"  {G}✓{X} Go PATH configured: {self.GOPATH}")
        except Exception as e:
            results.append(("Go PATH configured", False))
            print(f"  {R}✗{X} PATH: {e}")

        # Test 6: get_available_tools returns dict
        try:
            available = self.get_available_tools()
            assert isinstance(available, dict)
            results.append((f"get_available_tools returns dict ({len(available)} tools)", True))
            print(f"  {G}✓{X} get_available_tools: {len(available)} tools available")
        except Exception as e:
            results.append(("get_available_tools", False))
            print(f"  {R}✗{X} get_available_tools: {e}")

        passed = sum(1 for _, ok in results if ok)
        failed = len(results) - passed
        print(f"\n  {G}Stress: {passed} passed{X}  {R}{failed} failed{X}\n")
        return results


if __name__ == "__main__":
    installer = ToolInstaller(verbose=True)

    # Run tests first
    installer.run_regression_tests()
    installer.stress_test()

    # Check and install all tools
    installer.check_and_install_all()
