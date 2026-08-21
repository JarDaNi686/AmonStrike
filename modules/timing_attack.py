"""AmonStrike — Timing Attack Module"""
import time, statistics
from .base import BaseModule

class TimingAttackModule(BaseModule):
    NAME        = "timing_attack"
    DESCRIPTION = "Timing attacks — user enum, blind injection, hash comparison"

    SAMPLES = 5  # requests per test

    def run(self):
        self.log("Testing timing attacks...")
        self._test_login_timing()
        self._test_blind_sqli_timing()
        return self.result()

    def _test_login_timing(self):
        """Detect user enumeration via timing difference."""
        login_paths = ["/api/login","/api/auth","/login"]
        for path in login_paths:
            r = self.get(path)
            if not r or r.status_code == 404: continue

            valid_times, invalid_times = [], []

            for _ in range(self.SAMPLES):
                t0 = time.time()
                self.post(path, json={"username":"admin","password":"wrongpass_xyz"})
                valid_times.append(time.time()-t0)

            for _ in range(self.SAMPLES):
                t0 = time.time()
                self.post(path, json={"username":"nonexistent_xyz_abc123","password":"wrongpass_xyz"})
                invalid_times.append(time.time()-t0)

            avg_valid   = statistics.mean(valid_times)
            avg_invalid = statistics.mean(invalid_times)
            diff        = abs(avg_valid - avg_invalid)

            if diff > 0.1:  # 100ms difference = likely timing side-channel
                self.add_finding(
                    title       = f"Timing-Based User Enumeration at {path}",
                    severity    = "MEDIUM",
                    description = (
                        f"Login endpoint takes {diff*1000:.0f}ms longer for valid vs invalid users. "
                        "Timing side-channel enables silent user enumeration without error messages."
                    ),
                    evidence    = (
                        f"Path: {path}\n"
                        f"Valid username avg: {avg_valid*1000:.0f}ms\n"
                        f"Invalid username avg: {avg_invalid*1000:.0f}ms\n"
                        f"Difference: {diff*1000:.0f}ms"
                    ),
                    remediation = "Use constant-time comparison. Add uniform artificial delay to all login responses.",
                    url=self.url+path, cve="CWE-208",
                )

    def _test_blind_sqli_timing(self):
        """Time-based blind SQLi across all params."""
        for param in ["id","search","q","page","item"]:
            # MySQL sleep
            t0 = time.time()
            self.get(params={param: "1 AND SLEEP(4)"})
            elapsed = time.time()-t0
            if elapsed >= 3.8:
                self.add_finding(
                    title       = f"Blind SQL Injection (Time-based) — \'{param}\'",
                    severity    = "CRITICAL",
                    description = f"4s SLEEP injected via \'{param}\' caused {elapsed:.1f}s delay — blind SQLi confirmed.",
                    evidence    = f"Param: {param}\nPayload: 1 AND SLEEP(4)\nDelay: {elapsed:.1f}s",
                    remediation = "Use prepared statements. Never interpolate user input into SQL.",
                    url=self.url, parameter=param, payload="1 AND SLEEP(4)", cve="CWE-89",
                )
                break
