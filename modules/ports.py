"""AmonStrike — Port Scanning Module"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule

class PortModule(BaseModule):
    NAME = "ports"
    DESCRIPTION = "Port scanning — common web and service ports"

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 81: "HTTP-Alt", 443: "HTTPS",
        445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
        2181: "Zookeeper", 4848: "Glassfish", 7001: "WebLogic",
        8161: "ActiveMQ", 9090: "WebSphere", 4873: "npm Registry",
    }

    HIGH_RISK_PORTS = {
        23:    "Telnet — unencrypted protocol",
        21:    "FTP — unencrypted file transfer",
        1433:  "MSSQL — database exposed",
        3306:  "MySQL — database exposed",
        5432:  "PostgreSQL — database exposed",
        27017: "MongoDB — database exposed (no auth by default)",
        6379:  "Redis — in-memory store exposed (no auth by default)",
        9200:  "Elasticsearch — exposed without auth",
        3389:  "RDP — remote desktop exposed",
        5900:  "VNC — remote desktop exposed",
        445:   "SMB — file sharing exposed",
    }

    def run(self):
        self.log("Scanning common ports...")
        host = self.parsed.hostname
        open_ports = {}

        def check_port(port):
            try:
                sock = socket.create_connection((host, port), timeout=2)
                sock.close()
                return port
            except Exception:
                return None

        threads = self.session_data.get("threads", 20)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_port, p): p for p in self.COMMON_PORTS}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    service = self.COMMON_PORTS[port]
                    open_ports[port] = service
                    self.log(f"Open port: {port}/{service}", "i")

        self.info["open_ports"] = open_ports

        # Report high-risk ports
        for port, service in open_ports.items():
            if port in self.HIGH_RISK_PORTS:
                severity = "CRITICAL" if port in [27017, 6379, 9200] else "HIGH"
                self.add_finding(
                    title=f"High-Risk Port Open: {port}/{service}",
                    severity=severity,
                    description=f"Port {port} ({service}) is accessible from the network. {self.HIGH_RISK_PORTS[port]}",
                    evidence=f"Host: {host}:{port} → OPEN\nService: {service}",
                    remediation=f"Restrict access to port {port} using firewall rules. Only allow trusted IP ranges. Never expose {service} to the internet.",
                    url=f"{host}:{port}"
                )
            else:
                self.add_finding(
                    title=f"Open Port: {port}/{service}",
                    severity="INFO",
                    description=f"Port {port} ({service}) is open.",
                    evidence=f"Host: {host}:{port} → OPEN",
                    remediation="Review if this port needs to be publicly accessible.",
                    url=f"{host}:{port}"
                )

        self.log(f"Port scan complete — {len(open_ports)} open ports", "+")
        return self.result()
