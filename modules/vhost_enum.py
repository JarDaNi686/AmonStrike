"""AmonStrike — Virtual Host Enumeration Module"""
import re, socket
from .base import BaseModule

class VhostEnumModule(BaseModule):
    NAME        = "vhost_enum"
    DESCRIPTION = "Virtual host enumeration — find hidden vhosts, internal apps"

    def run(self):
        self.log("Enumerating virtual hosts...")
        host = self.parsed.hostname
        ip   = self._resolve(host)
        if not ip:
            return self.result()

        self.info["resolved_ip"] = ip
        found = self._brute_vhosts(host, ip)
        self.log(f"VHost enum complete — {len(found)} hidden vhosts", "+")
        return self.result()

    def _resolve(self, host: str) -> str:
        try: return socket.gethostbyname(host)
        except: return ""

    def _brute_vhosts(self, base: str, ip: str) -> list:
        domain = ".".join(base.split(".")[-2:])
        prefixes = [
            "admin","internal","dev","staging","test","api",
            "mail","smtp","ftp","vpn","jenkins","gitlab","jira",
            "confluence","grafana","kibana","monitor","dashboard",
            "backend","app","portal","intranet","corp","old",
            "beta","preview","secure","login","auth","sso",
        ]
        found = []
        r0 = self.get("")
        baseline = len(r0.text) if r0 else 0

        for prefix in prefixes:
            vhost = f"{prefix}.{domain}"
            try:
                r = self.session.get(
                    self.url, headers={"Host": vhost},
                    timeout=5, verify=False, allow_redirects=False
                )
                if r and r.status_code not in [400,404,500]:
                    diff = abs(len(r.text) - baseline)
                    if diff > 200:  # Different content = different vhost
                        found.append(vhost)
                        self.add_finding(
                            title       = f"Hidden Virtual Host Discovered: {vhost}",
                            severity    = "MEDIUM",
                            description = (
                                f"Virtual host {vhost} responds differently from the default host. "
                                "May be an internal application not intended to be public."
                            ),
                            evidence    = (
                                f"Host header: {vhost}\n"
                                f"Status: {r.status_code}\n"
                                f"Content diff: {diff} bytes\n"
                                f"Preview: {r.text[:150]}"
                            ),
                            remediation = "Restrict virtual hosts to expected domain names. Configure default host to return 444.",
                            url         = self.url, parameter="Host", payload=vhost, cve="CWE-284",
                        )
            except Exception: pass
        return found
