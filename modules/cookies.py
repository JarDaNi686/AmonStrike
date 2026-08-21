"""AmonStrike — Cookie Security Module"""
from .base import BaseModule

class CookiesModule(BaseModule):
    NAME = "cookies"
    DESCRIPTION = "Cookie security flags — HttpOnly, Secure, SameSite"

    def run(self):
        self.log("Analyzing cookie security flags...")
        resp = self.get()
        if not resp:
            return self.result()

        cookies = resp.cookies
        set_cookie_headers = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, 'getlist') else []

        # Parse raw Set-Cookie headers for flag analysis
        raw_cookies = []
        for h_name, h_val in resp.headers.items():
            if h_name.lower() == "set-cookie":
                raw_cookies.append(h_val)

        self.info["cookies_found"] = len(raw_cookies)

        for cookie_str in raw_cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0]
            name = name_val.split("=")[0] if "=" in name_val else name_val
            attrs = [p.lower() for p in parts[1:]]

            flags = {
                "httponly": "httponly" in attrs,
                "secure":   "secure" in attrs,
                "samesite": any("samesite" in a for a in attrs),
            }

            samesite_val = ""
            for a in attrs:
                if "samesite" in a:
                    samesite_val = a.split("=")[-1].strip() if "=" in a else "unknown"

            if not flags["httponly"]:
                self.add_finding(
                    title=f"Cookie Missing HttpOnly Flag: {name}",
                    severity="MEDIUM",
                    description=f"Cookie '{name}' does not have the HttpOnly flag. JavaScript can access this cookie, enabling XSS-based session hijacking.",
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    remediation=f"Add HttpOnly flag: Set-Cookie: {name}=value; HttpOnly; ...",
                    url=self.url,
                    cve="CWE-1004"
                )

            if self.parsed.scheme == "https" and not flags["secure"]:
                self.add_finding(
                    title=f"Cookie Missing Secure Flag: {name}",
                    severity="MEDIUM",
                    description=f"Cookie '{name}' does not have the Secure flag on an HTTPS site. Cookie may be transmitted over HTTP.",
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    remediation=f"Add Secure flag: Set-Cookie: {name}=value; Secure; ...",
                    url=self.url,
                    cve="CWE-614"
                )

            if not flags["samesite"]:
                self.add_finding(
                    title=f"Cookie Missing SameSite Flag: {name}",
                    severity="LOW",
                    description=f"Cookie '{name}' does not have SameSite attribute. May be vulnerable to CSRF.",
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    remediation=f"Add SameSite=Strict or SameSite=Lax: Set-Cookie: {name}=value; SameSite=Strict; ...",
                    url=self.url
                )
            elif samesite_val == "none" and not flags["secure"]:
                self.add_finding(
                    title=f"Cookie SameSite=None Without Secure: {name}",
                    severity="MEDIUM",
                    description=f"Cookie '{name}' has SameSite=None but no Secure flag. Modern browsers reject this.",
                    evidence=f"Set-Cookie: {cookie_str[:100]}",
                    remediation="Add Secure flag when using SameSite=None.",
                    url=self.url
                )

            # Check for session cookie names
            sensitive_names = ["session", "auth", "token", "jwt", "sid", "user", "login", "admin"]
            if any(s in name.lower() for s in sensitive_names):
                if not flags["httponly"] or not flags["secure"]:
                    self.add_finding(
                        title=f"Session/Auth Cookie Inadequately Protected: {name}",
                        severity="HIGH",
                        description=f"Cookie '{name}' is a session or auth cookie but is missing security flags.",
                        evidence=f"Cookie name: {name}\nHttpOnly: {flags['httponly']}\nSecure: {flags['secure']}\nSameSite: {flags['samesite']}",
                        remediation="Always set HttpOnly and Secure flags on session and authentication cookies.",
                        url=self.url,
                        cve="CWE-614"
                    )

        self.log(f"Cookie analysis complete — {len(self.findings)} findings", "+")
        return self.result()
