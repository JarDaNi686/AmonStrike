"""
AmonStrike — Port Scanner Module
Real socket scanning + nmap/naabu integration.
Finds exposed services that shouldn't be public.
"""
import socket
import subprocess
import concurrent.futures
from .base import BaseModule

INTERESTING_PORTS = {
    21:    ("FTP",        "File Transfer — often anonymous login"),
    22:    ("SSH",        "Remote shell — brute force target"),
    23:    ("Telnet",     "Unencrypted remote shell — critical"),
    25:    ("SMTP",       "Mail server — open relay check"),
    53:    ("DNS",        "DNS server — zone transfer risk"),
    80:    ("HTTP",       "Web server"),
    110:   ("POP3",       "Email retrieval — cleartext"),
    143:   ("IMAP",       "Email access — cleartext"),
    443:   ("HTTPS",      "Web server TLS"),
    445:   ("SMB",        "Windows shares — EternalBlue risk"),
    1433:  ("MSSQL",      "SQL Server — credential attack"),
    1521:  ("Oracle DB",  "Oracle database exposed"),
    2049:  ("NFS",        "Network filesystem — data exposure"),
    3000:  ("Dev Server", "Node/Rails dev — debug mode"),
    3306:  ("MySQL",      "MySQL exposed — credential attack"),
    3389:  ("RDP",        "Remote Desktop — brute force"),
    4443:  ("Alt HTTPS",  "Alternative HTTPS port"),
    5000:  ("Dev Server", "Flask/other dev server"),
    5432:  ("PostgreSQL", "Postgres exposed"),
    5900:  ("VNC",        "Remote desktop — often no auth"),
    6379:  ("Redis",      "Redis — often no auth, RCE possible"),
    7000:  ("Cassandra",  "Cassandra DB exposed"),
    8000:  ("Dev HTTP",   "Dev web server"),
    8080:  ("Alt HTTP",   "Alternative HTTP / proxy"),
    8443:  ("Alt HTTPS",  "Alternative HTTPS"),
    8888:  ("Jupyter",    "Jupyter Notebook — often no auth"),
    9200:  ("Elasticsearch","ES — no auth by default, data exposure"),
    9300:  ("ES Cluster", "Elasticsearch cluster comms"),
    27017: ("MongoDB",    "MongoDB — no auth by default"),
    27018: ("MongoDB",    "MongoDB shard"),
    50000: ("SAP",        "SAP application server"),
}

CRITICAL_PORTS    = {21,23,445,3389,5900,6379,9200,27017,8888}
HIGH_PORTS        = {22,25,1433,1521,3306,5432,4444,5000,8000}


class PortModule(BaseModule):
    NAME        = "ports"
    DESCRIPTION = "Port scanning — exposed services, dangerous open ports"

    def run(self):
        self.log("Scanning ports...")
        host = self.parsed.hostname

        # Try naabu first (fastest), then nmap, then raw sockets
        if self._naabu_available():
            self._scan_naabu(host)
        elif self._nmap_available():
            self._scan_nmap(host)
        else:
            self._scan_sockets(host)

        self.log(f"Port scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _scan_sockets(self, host: str):
        """Raw socket scan — no tools required."""
        self.log(f"Socket scanning {len(INTERESTING_PORTS)} ports on {host}...")
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            results = ex.map(check_port, INTERESTING_PORTS.keys())

        for port in results:
            if port:
                open_ports.append(port)
                self._process_port(host, port)

        self.info["open_ports"] = open_ports

    def _scan_nmap(self, host: str):
        """Nmap scan for service detection."""
        try:
            ports = ",".join(str(p) for p in INTERESTING_PORTS)
            out = subprocess.run(
                ["nmap","-sV","--open","-p",ports,"-T4","--host-timeout","60s",
                 "-oG","-", host],
                capture_output=True, text=True, timeout=120
            ).stdout

            import re
            for line in out.splitlines():
                for m in re.finditer(r'(\d+)/open', line):
                    port = int(m.group(1))
                    self._process_port(host, port)
        except Exception as e:
            self.log(f"nmap failed: {e} — falling back to sockets", "~")
            self._scan_sockets(host)

    def _scan_naabu(self, host: str):
        """Naabu scan (ProjectDiscovery)."""
        try:
            ports = ",".join(str(p) for p in INTERESTING_PORTS)
            out = subprocess.run(
                ["naabu","-host",host,"-p",ports,"-silent","-timeout","2000"],
                capture_output=True, text=True, timeout=90
            ).stdout
            import re
            for line in out.strip().splitlines():
                m = re.search(r':(\d+)$', line.strip())
                if m:
                    self._process_port(host, int(m.group(1)))
        except Exception:
            self._scan_sockets(host)

    def _process_port(self, host: str, port: int):
        """Evaluate an open port and add finding if interesting."""
        if port not in INTERESTING_PORTS:
            return
        service, desc = INTERESTING_PORTS[port]
        severity = (
            "CRITICAL" if port in CRITICAL_PORTS else
            "HIGH"     if port in HIGH_PORTS     else
            "MEDIUM"
        )
        # Try to grab banner
        banner = self._grab_banner(host, port)
        self.add_finding(
            title       = f"Exposed Service: {service} (port {port})",
            severity    = severity,
            description = f"{service} (port {port}) is open on {host}. {desc}.",
            evidence    = f"Host: {host}\nPort: {port}\nService: {service}\nBanner: {banner or 'N/A'}",
            remediation = (
                f"Firewall port {port} from public internet. "
                f"Use VPN or IP allowlist for administrative access."
            ),
            url = f"http://{host}:{port}",
            cve = self._known_cve(port),
        )

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((host, port))
            banner = s.recv(1024).decode("utf-8","replace").strip()[:100]
            s.close()
            return banner
        except Exception:
            return ""

    def _known_cve(self, port: int) -> str:
        cves = {
            6379:  "CVE-2022-0543",
            9200:  "CVE-2021-22145",
            27017: "CVE-2020-7921",
            445:   "CVE-2017-0144",
        }
        return cves.get(port, "")

    def _nmap_available(self) -> bool:
        import shutil
        return bool(shutil.which("nmap"))

    def _naabu_available(self) -> bool:
        import shutil
        return bool(shutil.which("naabu"))
