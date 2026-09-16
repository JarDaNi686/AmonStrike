"""
AmonStrike — Ghost Protocol
Mission Impossible level stealth and intelligence.

NOT malware. NOT AV evasion.
This is: identity rotation, timing intelligence,
behavioral mimicry, and fingerprint randomization
for authorized penetration testing.

Like Ethan Hunt: blend in, don't stand out.
Every request looks like a different legitimate user.
WAF never sees the same fingerprint twice.
"""

import random, time, hashlib, json
from datetime import datetime

# Real browser fingerprints from common user agents
BROWSER_PROFILES = [
    {
        "name":       "Chrome Windows",
        "ua":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "lang":       "en-US,en;q=0.9",
        "encoding":   "gzip, deflate, br",
        "sec_ch_ua":  '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "platform":   '"Windows"',
    },
    {
        "name":       "Safari macOS",
        "ua":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "lang":       "en-GB,en;q=0.9",
        "encoding":   "gzip, deflate, br",
        "sec_ch_ua":  "",
        "platform":   '"macOS"',
    },
    {
        "name":       "Firefox Linux",
        "ua":         "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "lang":       "en-US,en;q=0.5",
        "encoding":   "gzip, deflate, br, zstd",
        "sec_ch_ua":  "",
        "platform":   '"Linux"',
    },
    {
        "name":       "Chrome Android",
        "ua":         "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36",
        "accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "lang":       "en-US,en;q=0.9",
        "encoding":   "gzip, deflate, br",
        "sec_ch_ua":  '"Android WebView";v="126"',
        "platform":   '"Android"',
    },
    {
        "name":       "Edge Windows",
        "ua":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "lang":       "en-US,en;q=0.9",
        "encoding":   "gzip, deflate, br",
        "sec_ch_ua":  '"Microsoft Edge";v="126"',
        "platform":   '"Windows"',
    },
]

# Human-like timing distributions (milliseconds)
TIMING_PROFILES = {
    "human_fast":   (200,  800),   # fast typist browsing
    "human_normal": (800,  3000),  # average user
    "human_slow":   (2000, 8000),  # slow reader
    "api_client":   (50,   200),   # programmatic client
    "mobile_user":  (500,  2000),  # mobile user
}


class GhostProtocol:
    """
    Stealth layer for authorized penetration testing.
    Makes every request look like a different legitimate user.
    WAFs see organic traffic, not a scanner.
    """

    def __init__(self, profile: str = "rotating"):
        self.profile       = profile
        self.request_count = 0
        self.session_start = time.time()
        self._current_fp   = None
        self._rotate()

    def _rotate(self):
        """Rotate to a new browser fingerprint."""
        self._current_fp = random.choice(BROWSER_PROFILES)

    def get_headers(self, url: str = "", h1_handle: str = "jardani101") -> dict:
        """
        Generate realistic browser headers.
        Rotates profile every N requests.
        """
        self.request_count += 1
        if self.request_count % random.randint(8, 25) == 0:
            self._rotate()

        fp = self._current_fp
        h  = {
            "User-Agent":      fp["ua"],
            "Accept":          fp["accept"],
            "Accept-Language": fp["lang"],
            "Accept-Encoding": fp["encoding"],
            "X-HackerOne-Handle": h1_handle,
        }

        # Add Sec-CH-UA headers for Chromium-based browsers
        if fp["sec_ch_ua"]:
            h["Sec-CH-UA"]          = fp["sec_ch_ua"]
            h["Sec-CH-UA-Mobile"]   = "?0"
            h["Sec-CH-UA-Platform"] = fp["platform"]
            h["Sec-Fetch-Dest"]     = random.choice(["document","empty"])
            h["Sec-Fetch-Mode"]     = random.choice(["navigate","cors","no-cors"])
            h["Sec-Fetch-Site"]     = random.choice(["same-origin","cross-site","none"])

        # Realistic referrer
        if url and random.random() > 0.4:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            h["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"

        # Cache headers
        if random.random() > 0.6:
            h["Cache-Control"] = random.choice(["no-cache","max-age=0"])

        return h

    def human_delay(self, context: str = "normal"):
        """
        Sleep for a human-realistic duration.
        Context-aware: reading a page vs clicking a button.
        """
        profile_map = {
            "page_load":  "human_normal",
            "form_submit":"human_fast",
            "api_call":   "api_client",
            "reading":    "human_slow",
            "normal":     "human_normal",
        }
        profile = profile_map.get(context, "human_normal")
        lo, hi  = TIMING_PROFILES[profile]
        # Add natural jitter
        delay = random.uniform(lo, hi) / 1000  # convert to seconds
        delay += random.gauss(0, delay * 0.1)  # 10% gaussian jitter
        delay  = max(0.05, delay)               # minimum 50ms
        time.sleep(delay)

    def build_session(self, cookies: dict = None,
                      proxies: dict = None) -> "requests.Session":
        """Build a requests session with ghost profile."""
        import requests, urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify  = False
        s.headers.update(self.get_headers())
        if cookies:
            s.cookies.update(cookies)
        if proxies:
            s.proxies.update(proxies)
        return s

    def mission_briefing(self, target: str, scope: list) -> dict:
        """
        Pre-mission intelligence gathering.
        Public sources only. No active probing yet.
        """
        print(f"\n{'='*55}")
        print(f"  GHOST PROTOCOL — MISSION BRIEFING")
        print(f"  Target: {target}")
        print(f"{'='*55}\n")

        intel = {
            "target":        target,
            "scope":         scope,
            "passive_recon": {},
            "tech_stack":    [],
            "entry_points":  [],
        }

        # Passive OSINT — no requests to target yet
        from urllib.parse import urlparse
        domain = urlparse(target).netloc

        # Certificate transparency
        try:
            import requests as req
            r = req.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10, headers={"User-Agent": random.choice(BROWSER_PROFILES)["ua"]}
            )
            if r.status_code == 200:
                subs = list(set(
                    e.get("name_value","").lstrip("*.")
                    for e in r.json()
                    if domain in e.get("name_value","")
                ))
                intel["passive_recon"]["subdomains"] = subs[:30]
                print(f"  [PASSIVE] {len(subs)} subdomains from CT logs")
        except Exception:
            pass

        # Wayback Machine
        try:
            import requests as req
            r = req.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url":f"{domain}/*","output":"text",
                       "fl":"original","collapse":"urlkey","limit":"100"},
                timeout=10
            )
            if r.status_code == 200:
                urls = [u for u in r.text.splitlines() if "?" in u]
                intel["passive_recon"]["historical_urls"] = urls[:20]
                print(f"  [PASSIVE] {len(urls)} historical URLs")
        except Exception:
            pass

        return intel
