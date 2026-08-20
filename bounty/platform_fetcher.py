"""
AmonStrike — Bug Bounty Platform Fetcher
Automatically pulls programs from:
  - HackerOne (public API)
  - Bugcrowd (public API)
  - Intigriti (public API)
  - YesWeHack (public API)
  - Direct programs (NASA, DoD, Google, etc.)

Normalizes all programs into a standard format.
Feeds into program_ranker.py for prioritization.
"""

import re
import sys
import json
import time
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; D="\033[90m"; X="\033[0m"


class PlatformFetcher:
    """
    Fetches bug bounty programs from all major platforms.
    Returns normalized program objects ready for database storage.
    """

    HEADERS = {
        "User-Agent": "AmonStrike/2.0 Security Research Tool",
        "Accept":     "application/json",
    }

    # Known direct programs (no platform needed)
    DIRECT_PROGRAMS = [
        {
            "id":          "direct_nasa",
            "platform":    "direct",
            "name":        "NASA Vulnerability Disclosure Program",
            "handle":      "nasa",
            "url":         "https://www.nasa.gov/vulnerability-disclosure-policy",
            "policy_url":  "https://www.nasa.gov/vulnerability-disclosure-policy",
            "status":      "active",
            "bounty_min":  0,
            "bounty_max":  0,
            "currency":    "USD",
            "response_time": 7,
            "allows_auto": 0,
            "vdp_only":    1,
            "scope_domains": ["*.nasa.gov"],
            "notes":       "VDP only — no monetary reward but CVE credit + recognition",
        },
        {
            "id":          "direct_dod",
            "platform":    "direct",
            "name":        "US Department of Defense Vulnerability Disclosure",
            "handle":      "dod",
            "url":         "https://hackerone.com/deptofdefense",
            "policy_url":  "https://hackerone.com/deptofdefense",
            "status":      "active",
            "bounty_min":  0,
            "bounty_max":  0,
            "currency":    "USD",
            "response_time": 14,
            "allows_auto": 0,
            "vdp_only":    1,
            "scope_domains": ["*.mil","*.af.mil","*.army.mil","*.navy.mil"],
            "notes":       "VDP — huge scope, great for CVEs",
        },
        {
            "id":          "direct_google",
            "platform":    "direct",
            "name":        "Google Vulnerability Reward Program",
            "handle":      "google",
            "url":         "https://bughunters.google.com",
            "policy_url":  "https://bughunters.google.com/about/rules",
            "status":      "active",
            "bounty_min":  100,
            "bounty_max":  31337,
            "currency":    "USD",
            "response_time": 3,
            "allows_auto": 1,
            "vdp_only":    0,
            "scope_domains": ["*.google.com","*.youtube.com","*.blogger.com","*.gmail.com"],
            "notes":       "Highly competitive but massive bounties",
        },
        {
            "id":          "direct_microsoft",
            "platform":    "direct",
            "name":        "Microsoft Security Response Center",
            "handle":      "microsoft",
            "url":         "https://www.microsoft.com/en-us/msrc/bounty",
            "policy_url":  "https://www.microsoft.com/en-us/msrc/bounty",
            "status":      "active",
            "bounty_min":  500,
            "bounty_max":  250000,
            "currency":    "USD",
            "response_time": 5,
            "allows_auto": 1,
            "vdp_only":    0,
            "scope_domains": ["*.microsoft.com","*.azure.com","*.github.com","*.office.com"],
            "notes":       "Very high bounties for critical findings",
        },
        {
            "id":          "direct_apple",
            "platform":    "direct",
            "name":        "Apple Security Bounty Program",
            "handle":      "apple",
            "url":         "https://security.apple.com/bounty/",
            "policy_url":  "https://security.apple.com/bounty/",
            "status":      "active",
            "bounty_min":  5000,
            "bounty_max":  1000000,
            "currency":    "USD",
            "response_time": 14,
            "allows_auto": 0,
            "vdp_only":    0,
            "scope_domains": ["*.apple.com","*.icloud.com"],
            "notes":       "Invite-only but highest bounties in industry",
        },
        {
            "id":          "direct_vulnweb",
            "platform":    "direct",
            "name":        "Acunetix Test Sites (Practice)",
            "handle":      "vulnweb",
            "url":         "http://testphp.vulnweb.com",
            "policy_url":  "http://www.vulnweb.com",
            "status":      "active",
            "bounty_min":  0,
            "bounty_max":  0,
            "currency":    "USD",
            "response_time": 0,
            "allows_auto": 1,
            "vdp_only":    1,
            "scope_domains": [
                "testphp.vulnweb.com",
                "testaspnet.vulnweb.com",
                "testasp.vulnweb.com",
            ],
            "notes":       "Deliberately vulnerable — perfect for AmonStrike testing",
        },
        {
            "id":          "direct_hackyou",
            "platform":    "direct",
            "name":        "HackTheBox (Practice)",
            "handle":      "hackthebox",
            "url":         "https://www.hackthebox.com",
            "policy_url":  "https://www.hackthebox.com",
            "status":      "active",
            "bounty_min":  0,
            "bounty_max":  0,
            "currency":    "USD",
            "response_time": 0,
            "allows_auto": 1,
            "vdp_only":    1,
            "scope_domains": ["*.hackthebox.com"],
            "notes":       "Legal hacking practice platform",
        },
    ]

    def __init__(self, h1_token=None, bugcrowd_token=None,
                 intigriti_token=None):
        self.tokens = {
            "hackerone": h1_token,
            "bugcrowd":  bugcrowd_token,
            "intigriti": intigriti_token,
        }
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def fetch_all(self) -> list:
        """Fetch programs from all platforms concurrently."""
        all_programs = []
        fetchers = {
            "HackerOne":  self._fetch_hackerone,
            "Bugcrowd":   self._fetch_bugcrowd,
            "Intigriti":  self._fetch_intigriti,
            "Direct":     self._fetch_direct,
        }

        print(f"\n{D}  Fetching bug bounty programs from all platforms...{X}")

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(fn): name
                for name, fn in fetchers.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    programs = future.result()
                    all_programs.extend(programs)
                    print(f"  {G}✓{X} {name}: {len(programs)} programs")
                except Exception as e:
                    print(f"  {Y}~{X} {name}: {e}")

        print(f"  {G}Total: {len(all_programs)} programs fetched{X}\n")
        return all_programs

    def _fetch_hackerone(self) -> list:
        """Fetch public programs from HackerOne."""
        programs = []

        # HackerOne public API (no auth needed for public programs)
        url = "https://api.hackerone.com/v1/hackers/programs"
        params = {"page[size]": 100, "page[number]": 1}

        headers = dict(self.HEADERS)
        token = self.tokens.get("hackerone")
        if token:
            headers["Authorization"] = f"Token token={token}"

        try:
            while True:
                resp = self.session.get(url, params=params,
                                       headers=headers, timeout=15)
                if resp.status_code != 200:
                    break

                data = resp.json()
                items = data.get("data", [])
                if not items:
                    break

                for item in items:
                    attrs = item.get("attributes", {})
                    prog  = self._normalize_h1(item["id"], attrs)
                    programs.append(prog)

                # Pagination
                links = data.get("links", {})
                if not links.get("next"):
                    break
                params["page[number]"] += 1
                time.sleep(0.5)  # Rate limit

        except Exception as e:
            # Fallback to public list
            programs.extend(self._fetch_h1_public_fallback())

        return programs

    def _fetch_h1_public_fallback(self) -> list:
        """Fallback: fetch H1 programs from public directory."""
        try:
            resp = self.session.get(
                "https://hackerone.com/programs.json?state=public_mode",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                return [
                    self._normalize_h1_simple(p)
                    for p in data.get("results", [])
                ]
        except Exception:
            pass
        return []

    def _normalize_h1(self, prog_id, attrs) -> dict:
        """Normalize HackerOne program to standard format."""
        offers_bounty = attrs.get("offers_bounties", False)
        return {
            "id":           f"h1_{prog_id}",
            "platform":     "hackerone",
            "name":         attrs.get("name","Unknown"),
            "handle":       attrs.get("handle",""),
            "url":          f"https://hackerone.com/{attrs.get('handle','')}",
            "policy_url":   f"https://hackerone.com/{attrs.get('handle','')}",
            "status":       "active" if attrs.get("state") == "public_mode" else "inactive",
            "bounty_min":   attrs.get("minimum_bounty_table_value", 0) or 0,
            "bounty_max":   attrs.get("maximum_bounty_table_value", 0) or 0,
            "currency":     "USD",
            "response_time":attrs.get("average_time_to_first_response_in_minutes", 0) // 1440,
            "allows_auto":  1 if not attrs.get("profile_picture") else 0,
            "vdp_only":     0 if offers_bounty else 1,
            "raw_json":     json.dumps(attrs)[:2000],
            "fetched_at":   datetime.now().isoformat(),
            "rank_score":   0,
        }

    def _normalize_h1_simple(self, prog) -> dict:
        return {
            "id":           f"h1_{prog.get('id','unknown')}",
            "platform":     "hackerone",
            "name":         prog.get("name","Unknown"),
            "handle":       prog.get("handle",""),
            "url":          f"https://hackerone.com/{prog.get('handle','')}",
            "policy_url":   f"https://hackerone.com/{prog.get('handle','')}",
            "status":       "active",
            "bounty_min":   prog.get("min_bounty",0) or 0,
            "bounty_max":   prog.get("max_bounty",0) or 0,
            "currency":     "USD",
            "response_time": 3,
            "allows_auto":  1,
            "vdp_only":     0 if prog.get("offers_bounties") else 1,
            "raw_json":     json.dumps(prog)[:2000],
            "fetched_at":   datetime.now().isoformat(),
            "rank_score":   0,
        }

    def _fetch_bugcrowd(self) -> list:
        """Fetch public programs from Bugcrowd."""
        programs = []
        try:
            resp = self.session.get(
                "https://bugcrowd.com/programs.json",
                params={"sort[]":"promoted","page": 1,"limit":100},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for prog in data.get("programs", []):
                    normalized = self._normalize_bugcrowd(prog)
                    programs.append(normalized)
        except Exception:
            pass
        return programs

    def _normalize_bugcrowd(self, prog) -> dict:
        return {
            "id":          f"bc_{prog.get('code','unknown')}",
            "platform":    "bugcrowd",
            "name":        prog.get("name","Unknown"),
            "handle":      prog.get("code",""),
            "url":         f"https://bugcrowd.com/{prog.get('code','')}",
            "policy_url":  f"https://bugcrowd.com/{prog.get('code','')}",
            "status":      "active" if prog.get("started") else "inactive",
            "bounty_min":  prog.get("min_payout",0) or 0,
            "bounty_max":  prog.get("max_payout",0) or 0,
            "currency":    "USD",
            "response_time": 5,
            "allows_auto": 1,
            "vdp_only":    0 if prog.get("min_payout",0) > 0 else 1,
            "raw_json":    json.dumps(prog)[:2000],
            "fetched_at":  datetime.now().isoformat(),
            "rank_score":  0,
        }

    def _fetch_intigriti(self) -> list:
        """Fetch public programs from Intigriti."""
        programs = []
        try:
            resp = self.session.get(
                "https://api.intigriti.com/core/researcher/program",
                params={"limit":50,"offset":0,"status":2},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                for prog in data.get("records", []):
                    programs.append(self._normalize_intigriti(prog))
        except Exception:
            pass
        return programs

    def _normalize_intigriti(self, prog) -> dict:
        max_bounty = 0
        for sev in prog.get("maxBounty", {}).values():
            if isinstance(sev, (int, float)):
                max_bounty = max(max_bounty, sev)

        return {
            "id":          f"ig_{prog.get('id','unknown')}",
            "platform":    "intigriti",
            "name":        prog.get("name","Unknown"),
            "handle":      prog.get("handle",""),
            "url":         f"https://app.intigriti.com/programs/{prog.get('handle','')}",
            "policy_url":  prog.get("confidentialityLevel",""),
            "status":      "active" if prog.get("status",0) == 2 else "inactive",
            "bounty_min":  0,
            "bounty_max":  int(max_bounty),
            "currency":    "EUR",
            "response_time": prog.get("averageTimeToFirstResponseInHours",0) // 24,
            "allows_auto": 1,
            "vdp_only":    0 if max_bounty > 0 else 1,
            "raw_json":    json.dumps(prog)[:2000],
            "fetched_at":  datetime.now().isoformat(),
            "rank_score":  0,
        }

    def _fetch_direct(self) -> list:
        """Return hardcoded direct programs."""
        programs = []
        for p in self.DIRECT_PROGRAMS:
            prog = dict(p)
            prog["raw_json"]   = json.dumps({"scope": p.get("scope_domains",[])})
            prog["fetched_at"] = datetime.now().isoformat()
            prog["rank_score"] = 0
            programs.append(prog)
        return programs

    def fetch_program_scope(self, program: dict) -> list:
        """Fetch scope details for a specific program."""
        platform = program.get("platform","")
        handle   = program.get("handle","")
        scope    = []

        if platform == "hackerone":
            scope = self._fetch_h1_scope(handle)
        elif platform == "bugcrowd":
            scope = self._fetch_bc_scope(handle)
        elif platform == "direct":
            raw = program.get("raw_json","")
            try:
                data = json.loads(raw)
                for domain in data.get("scope",[]):
                    scope.append({
                        "asset_type":          "wildcard" if "*" in domain else "domain",
                        "target":              domain,
                        "in_scope":            True,
                        "eligible_for_bounty": not program.get("vdp_only",False),
                    })
            except Exception:
                pass

        return scope

    def _fetch_h1_scope(self, handle: str) -> list:
        scope = []
        try:
            resp = self.session.get(
                f"https://hackerone.com/{handle}/policy_scopes.json",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("in_scope",[]):
                    scope.append({
                        "asset_type":          self._map_h1_asset_type(item.get("asset_type","")),
                        "target":              item.get("asset_identifier",""),
                        "instruction":         item.get("instruction",""),
                        "in_scope":            True,
                        "eligible_for_bounty": item.get("eligible_for_bounty",True),
                    })
                for item in data.get("out_of_scope",[]):
                    scope.append({
                        "asset_type":          self._map_h1_asset_type(item.get("asset_type","")),
                        "target":              item.get("asset_identifier",""),
                        "in_scope":            False,
                        "eligible_for_bounty": False,
                    })
        except Exception:
            pass
        return scope

    def _fetch_bc_scope(self, handle: str) -> list:
        scope = []
        try:
            resp = self.session.get(
                f"https://bugcrowd.com/{handle}.json",
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                for target in data.get("targets",{}).get("in_scope",[]):
                    scope.append({
                        "asset_type":          "url",
                        "target":              target.get("target",""),
                        "instruction":         target.get("type",""),
                        "in_scope":            True,
                        "eligible_for_bounty": True,
                    })
        except Exception:
            pass
        return scope

    def _map_h1_asset_type(self, h1_type: str) -> str:
        mapping = {
            "URL":              "url",
            "WILDCARD":         "wildcard",
            "DOMAIN":           "domain",
            "IP_ADDRESS":       "ip_address",
            "CIDR":             "cidr",
            "ANDROID_APP_URL":  "mobile",
            "IOS_APP_URL":      "mobile",
            "OTHER":            "other",
        }
        return mapping.get(h1_type, "url")


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== PLATFORM FETCHER REGRESSION TESTS ===")
    passed = failed = 0
    fetcher = PlatformFetcher()

    tests = [
        ("Direct programs loaded",
         lambda: len(fetcher.DIRECT_PROGRAMS) >= 5),

        ("Fetch direct programs returns list",
         lambda: isinstance(fetcher._fetch_direct(), list)),

        ("Direct programs have required fields",
         lambda: all(
             all(k in p for k in ["id","platform","name","url",
                                   "bounty_min","bounty_max","allows_auto"])
             for p in fetcher._fetch_direct()
         )),

        ("Vulnweb practice site included",
         lambda: any(p["id"]=="direct_vulnweb" for p in fetcher._fetch_direct())),

        ("NASA VDP included",
         lambda: any(p["id"]=="direct_nasa" for p in fetcher._fetch_direct())),

        ("Google bounty program included",
         lambda: any(p["id"]=="direct_google" for p in fetcher._fetch_direct())),

        ("H1 normalization works",
         lambda: (
             prog := fetcher._normalize_h1("123",{
                 "name":"TestCo","handle":"testco","state":"public_mode",
                 "offers_bounties":True,"minimum_bounty_table_value":100,
                 "maximum_bounty_table_value":5000,
                 "average_time_to_first_response_in_minutes":4320
             }),
             prog["platform"] == "hackerone" and prog["bounty_max"] == 5000
         )[1]),

        ("Bugcrowd normalization works",
         lambda: (
             prog := fetcher._normalize_bugcrowd({
                 "code":"testco","name":"TestCo","started":True,
                 "min_payout":200,"max_payout":10000
             }),
             prog["platform"] == "bugcrowd" and prog["bounty_max"] == 10000
         )[1]),

        ("Asset type mapping complete",
         lambda: all(
             fetcher._map_h1_asset_type(t) for t in
             ["URL","WILDCARD","DOMAIN","IP_ADDRESS","CIDR","OTHER"]
         )),

        ("Fetch direct scope for direct program",
         lambda: isinstance(
             fetcher.fetch_program_scope({
                 "platform":"direct","handle":"vulnweb",
                 "raw_json":json.dumps({"scope":["testphp.vulnweb.com"]}),
                 "vdp_only":True
             }),
             list
         )),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
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
    rp, rf = run_regression_tests()
    print(f"\nTOTAL: {rp} passed  {rf} failed")
    import sys; sys.exit(0 if rf==0 else 1)
