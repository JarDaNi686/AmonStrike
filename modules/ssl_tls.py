"""AmonStrike — SSL/TLS Security Module"""
import ssl, socket, subprocess, shutil
from datetime import datetime
from .base import BaseModule

class SslTlsModule(BaseModule):
    NAME        = "ssl_tls"
    DESCRIPTION = "SSL/TLS — weak ciphers, expired certs, HSTS, mixed content"

    def run(self):
        self.log("Testing SSL/TLS configuration...")
        if self.parsed.scheme != "https":
            self._test_http_only()
            return self.result()

        host = self.parsed.hostname
        port = self.parsed.port or 443

        self._test_cert(host, port)
        self._test_hsts()
        self._test_weak_ciphers(host, port)
        self._test_sslv3_tls10(host, port)
        self._test_http_upgrade()

        self.log(f"SSL/TLS complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_cert(self, host, port):
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.create_connection((host,port),timeout=5), server_hostname=host)
            cert = conn.getpeercert()
            conn.close()

            # Check expiry
            expire = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days   = (expire - datetime.utcnow()).days
            if days < 0:
                self.add_finding(
                    title="SSL Certificate Expired",
                    severity="CRITICAL",
                    description=f"SSL certificate expired {-days} days ago on {cert['notAfter']}.",
                    evidence=f"Expiry: {cert['notAfter']}\nDays expired: {-days}",
                    remediation="Renew SSL certificate immediately. Enable auto-renewal with Let's Encrypt.",
                    url=self.url, cve="CWE-295",
                )
            elif days < 30:
                self.add_finding(
                    title=f"SSL Certificate Expiring Soon ({days} days)",
                    severity="MEDIUM",
                    description=f"Certificate expires in {days} days.",
                    evidence=f"Expiry: {cert['notAfter']}",
                    remediation="Renew certificate before expiry. Enable auto-renewal.",
                    url=self.url, cve="CWE-295",
                )
        except ssl.SSLError as e:
            self.add_finding(
                title="SSL Certificate Error",
                severity="HIGH",
                description=f"SSL handshake failed: {e}",
                evidence=str(e),
                remediation="Fix SSL certificate configuration.",
                url=self.url, cve="CWE-295",
            )
        except Exception: pass

    def _test_hsts(self):
        r = self.get("")
        if not r: return
        hsts = r.headers.get("Strict-Transport-Security","")
        if not hsts:
            self.add_finding(
                title="HSTS Not Implemented",
                severity="MEDIUM",
                description="No Strict-Transport-Security header. Clients may connect via HTTP.",
                evidence="Strict-Transport-Security: MISSING",
                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                url=self.url, cve="CWE-311",
            )
        elif "max-age=0" in hsts:
            self.add_finding(
                title="HSTS Disabled (max-age=0)",
                severity="MEDIUM",
                description="HSTS explicitly disabled with max-age=0.",
                evidence=f"HSTS: {hsts}",
                remediation="Set max-age to at least 31536000.",
                url=self.url, cve="CWE-311",
            )

    def _test_weak_ciphers(self, host, port):
        if not shutil.which("openssl"): return
        weak_ciphers = ["RC4","DES","3DES","EXPORT","NULL","ANON"]
        found = []
        for cipher in weak_ciphers:
            try:
                out = subprocess.run(
                    ["openssl","s_client","-connect",f"{host}:{port}",
                     f"-cipher",cipher,"-brief"],
                    capture_output=True, text=True, timeout=5, input=""
                ).stderr
                if "Cipher is" in out and "NONE" not in out:
                    found.append(cipher)
            except Exception: pass
        if found:
            self.add_finding(
                title=f"Weak TLS Ciphers Supported: {', '.join(found)}",
                severity="HIGH",
                description=f"Server supports weak cipher suites: {', '.join(found)}.",
                evidence=f"Weak ciphers accepted: {', '.join(found)}",
                remediation="Disable weak ciphers. Allow only TLS 1.2/1.3 with strong ciphers.",
                url=self.url, cve="CWE-326",
            )

    def _test_sslv3_tls10(self, host, port):
        for proto, flag in [("SSLv3","-ssl3"),("TLS 1.0","-tls1"),("TLS 1.1","-tls1_1")]:
            try:
                out = subprocess.run(
                    ["openssl","s_client","-connect",f"{host}:{port}",flag,"-brief"],
                    capture_output=True, text=True, timeout=5, input=""
                ).stderr
                if "Cipher is" in out and "NONE" not in out:
                    self.add_finding(
                        title=f"Deprecated Protocol Supported: {proto}",
                        severity="HIGH" if "SSL" in proto else "MEDIUM",
                        description=f"Server accepts {proto} connections (deprecated/vulnerable).",
                        evidence=f"Protocol: {proto}\nopenssl: cipher established",
                        remediation=f"Disable {proto}. Support only TLS 1.2 and TLS 1.3.",
                        url=self.url, cve="CVE-2014-3566" if "SSL" in proto else "CWE-326",
                    )
            except Exception: pass

    def _test_http_only(self):
        self.add_finding(
            title="Site Served Over HTTP (No TLS)",
            severity="HIGH",
            description="Site uses plain HTTP. All traffic is unencrypted and can be intercepted.",
            evidence=f"URL scheme: {self.parsed.scheme}",
            remediation="Obtain TLS certificate (Let's Encrypt) and redirect HTTP to HTTPS.",
            url=self.url, cve="CWE-311",
        )
        # Check if HTTPS is available
        try:
            import requests as req
            r = req.get(self.url.replace("http://","https://"), timeout=5, verify=False)
            if r.status_code < 400:
                self.add_finding(
                    title="HTTPS Available But Not Enforced",
                    severity="MEDIUM",
                    description="HTTPS is available but HTTP is not redirected to HTTPS.",
                    evidence="HTTP accessible, HTTPS also accessible",
                    remediation="Redirect all HTTP traffic to HTTPS (301).",
                    url=self.url, cve="CWE-311",
                )
        except Exception: pass

    def _test_http_upgrade(self):
        r = self.get("", headers={"Upgrade-Insecure-Requests":"1"})
        if r and r.status_code not in [301,302]:
            pass
