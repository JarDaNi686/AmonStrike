#!/usr/bin/env python3
"""
AmonStrike — HackerOne Live Scope Fetcher

Replaces hardcoded YAML with a live call to HackerOne's
structured_scopes API.  Returns a program config dict
in the same shape as configs/*.yaml so the rest of the
pipeline needs no changes.

Usage (standalone):
    python3 core/h1_scope_fetcher.py --handle gocardless
    python3 core/h1_scope_fetcher.py --handle anthropic --save

Usage (library):
    from core.h1_scope_fetcher import H1ScopeFetcher
    cfg = H1ScopeFetcher(h1_user, h1_token).fetch("gocardless")
    scope = H1ScopeFetcher(h1_user, h1_token).build_scope_validator("gocardless")
"""

import json
import time
import requests
from pathlib import Path
from datetime import datetime


class H1ScopeFetcher:
    """
    Fetches live scope data from HackerOne API and converts it to
    the AmonStrike program config format.
    """

    H1_API = "https://api.hackerone.com/v1"
    CACHE_DIR = Path("data/scope_cache")
    CACHE_TTL = 3600  # seconds — re-fetch after 1 hour

    ASSET_TYPE_MAP = {
        "URL":             "url",
        "WILDCARD":        "wildcard",
        "DOMAIN":          "domain",
        "IP_ADDRESS":      "ip",
        "CIDR":            "cidr",
        "ANDROID_APP_URL": "mobile",
        "IOS_APP_URL":     "mobile",
        "SOURCE_CODE":     "source_code",
        "OTHER":           "other",
    }

    def __init__(self, h1_username: str = "", h1_token: str = ""):
        self.auth = (h1_username, h1_token) if h1_username and h1_token else None
        self.session = requests.Session()
        self.session.headers.update({
            "Accept":     "application/json",
            "User-Agent": "AmonStrike/2.0 Security Research Tool",
        })
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────

    def fetch(self, handle: str, use_cache: bool = True) -> dict:
        """
        Fetch program config for the given H1 handle.
        Returns a dict in the same shape as configs/*.yaml.
        """
        if use_cache:
            cached = self._load_cache(handle)
            if cached:
                return cached

        program = self._fetch_program(handle)
        scopes  = self._fetch_scopes(handle)
        config  = self._build_config(handle, program, scopes)

        self._save_cache(handle, config)
        return config

    def build_scope_validator(self, handle: str) -> "ScopeValidator":
        """Return a ScopeValidator built from live H1 scope."""
        from core.scope_validator import ScopeValidator
        cfg     = self.fetch(handle)
        allowed  = cfg.get("core_assets", []) + cfg.get("non_core_assets", [])
        forbidden = cfg.get("forbidden_hosts", [])
        from urllib.parse import urlparse
        hosts = [urlparse("https://" + h if "://" not in h else h).hostname
                 for h in allowed]
        hosts = [h for h in hosts if h]
        return ScopeValidator(custom_scope=hosts, forbidden_hosts=forbidden)

    def fetch_and_save_yaml(self, handle: str, out_dir: str = "configs") -> str:
        """Fetch scope and write a YAML config file. Returns path."""
        import yaml
        cfg  = self.fetch(handle)
        path = Path(out_dir) / f"{handle}_program.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
        print(f"[H1Scope] Saved: {path}")
        return str(path)

    # ── HackerOne API calls ───────────────────────────────────

    def _fetch_program(self, handle: str) -> dict:
        """Fetch program metadata from H1 API."""
        url = f"{self.H1_API}/hackers/programs/{handle}"
        try:
            resp = self.session.get(url, auth=self.auth, timeout=15)
            if resp.status_code == 200:
                data  = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                return {
                    "name":          attrs.get("name", handle),
                    "handle":        handle,
                    "state":         attrs.get("state", "public_mode"),
                    "offers_bounty": attrs.get("offers_bounties", False),
                    "bounty_min":    attrs.get("minimum_bounty_table_value", 0) or 0,
                    "bounty_max":    attrs.get("maximum_bounty_table_value", 0) or 0,
                    "response_time": attrs.get("average_time_to_first_response_in_minutes", 0) // 1440,
                }
            # Fallback: public directory
            return self._fetch_program_public(handle)
        except Exception:
            return self._fetch_program_public(handle)

    def _fetch_program_public(self, handle: str) -> dict:
        """Fallback: parse public program page JSON."""
        try:
            resp = self.session.get(
                f"https://hackerone.com/{handle}.json",
                timeout=10,
            )
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "name":          d.get("name", handle),
                    "handle":        handle,
                    "state":         "public_mode",
                    "offers_bounty": d.get("offers_bounties", False),
                    "bounty_min":    0,
                    "bounty_max":    0,
                    "response_time": 7,
                }
        except Exception:
            pass
        return {"name": handle, "handle": handle, "state": "public_mode",
                "offers_bounty": False, "bounty_min": 0, "bounty_max": 0,
                "response_time": 7}

    def _fetch_scopes(self, handle: str) -> dict:
        """
        Fetch structured_scopes from H1 API.
        Returns {"in_scope": [...], "out_of_scope": [...]}
        """
        # Authenticated endpoint
        url = f"{self.H1_API}/hackers/programs/{handle}/structured_scopes"
        try:
            resp = self.session.get(url, auth=self.auth, timeout=15)
            if resp.status_code == 200:
                items = resp.json().get("data", [])
                return self._split_scopes(items)
        except Exception:
            pass

        # Unauthenticated public fallback
        try:
            resp = self.session.get(
                f"https://hackerone.com/{handle}/policy_scopes.json",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "in_scope":  data.get("in_scope", []),
                    "out_scope": data.get("out_of_scope", []),
                }
        except Exception:
            pass

        return {"in_scope": [], "out_scope": []}

    def _split_scopes(self, items: list) -> dict:
        """Split structured_scope items into in/out."""
        in_scope  = []
        out_scope = []
        for item in items:
            attrs = item.get("attributes", {}) if "attributes" in item else item
            entry = {
                "asset_type":          self.ASSET_TYPE_MAP.get(
                                           attrs.get("asset_type", "OTHER"), "other"),
                "target":              attrs.get("asset_identifier", ""),
                "instruction":         attrs.get("instruction", ""),
                "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                "max_severity":        attrs.get("max_severity", ""),
            }
            if attrs.get("eligible_for_submission", True):
                in_scope.append(entry)
            else:
                out_scope.append(entry)
        return {"in_scope": in_scope, "out_scope": out_scope}

    # ── Config builder ────────────────────────────────────────

    def _build_config(self, handle: str, program: dict, scopes: dict) -> dict:
        """Build AmonStrike-compatible config dict from H1 data."""
        in_scope  = scopes.get("in_scope", [])
        out_scope = scopes.get("out_scope", [])

        # Separate core (bounty-eligible) from non-core assets
        core_assets     = []
        non_core_assets = []
        forbidden_hosts = []

        for item in in_scope:
            target = item.get("target", "")
            if not target:
                continue
            atype = item.get("asset_type", "")
            if atype not in ("url", "wildcard", "domain"):
                continue
            # Strip URL scheme for scope list
            clean = target.replace("https://", "").replace("http://", "").rstrip("/")
            if item.get("eligible_for_bounty"):
                core_assets.append(clean)
            else:
                non_core_assets.append(clean)

        for item in out_scope:
            target = item.get("target", "")
            if not target:
                continue
            clean = target.replace("https://", "").replace("http://", "").rstrip("/")
            forbidden_hosts.append(clean)

        # Deduplicate
        core_assets     = list(dict.fromkeys(core_assets))
        non_core_assets = list(dict.fromkeys(non_core_assets))
        forbidden_hosts = list(dict.fromkeys(forbidden_hosts))

        config = {
            "program": {
                "handle":   handle,
                "platform": "hackerone",
                "name":     program.get("name", handle),
                "fetched":  datetime.utcnow().isoformat() + "Z",
            },
            "handle":       handle,
            "rate_limit":   3,
            "delay":        1.0,
            "core_assets":     core_assets     or [f"*.{handle}.com"],
            "non_core_assets": non_core_assets,
            "forbidden_hosts": forbidden_hosts,
            "scope_raw":    {
                "in_scope":  in_scope,
                "out_scope": out_scope,
            },
        }
        return config

    # ── Cache helpers ─────────────────────────────────────────

    def _cache_path(self, handle: str) -> Path:
        return self.CACHE_DIR / f"{handle}.json"

    def _load_cache(self, handle: str) -> dict:
        path = self._cache_path(handle)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text())
            age  = time.time() - data.get("_cached_at", 0)
            if age < self.CACHE_TTL:
                print(f"[H1Scope] Using cached scope for {handle} ({int(age)}s old)")
                return data
        except Exception:
            pass
        return {}

    def _save_cache(self, handle: str, config: dict):
        try:
            data = dict(config)
            data["_cached_at"] = time.time()
            self._cache_path(handle).write_text(json.dumps(data, indent=2))
        except Exception:
            pass


# ── Regression tests ─────────────────────────────────────────

def run_regression_tests():
    print("\n=== H1 SCOPE FETCHER REGRESSION TESTS ===")
    passed = failed = 0

    fetcher = H1ScopeFetcher()  # no auth — tests use mock data

    # Mock structured_scope items (API format)
    mock_items = [
        {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.example.com",
                        "eligible_for_bounty": True, "eligible_for_submission": True,
                        "instruction": "All subdomains"}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.example.com",
                        "eligible_for_bounty": True, "eligible_for_submission": True,
                        "instruction": "API"}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://staging.example.com",
                        "eligible_for_bounty": False, "eligible_for_submission": True,
                        "instruction": "No bounty"}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://internal.example.com",
                        "eligible_for_bounty": False, "eligible_for_submission": False,
                        "instruction": "OOS"}},
        {"attributes": {"asset_type": "ANDROID_APP_URL",
                        "asset_identifier": "com.example.app",
                        "eligible_for_bounty": True, "eligible_for_submission": True}},
    ]

    mock_program = {
        "name": "ExampleCo", "handle": "example",
        "state": "public_mode", "offers_bounty": True,
        "bounty_min": 100, "bounty_max": 10000, "response_time": 3,
    }

    scopes = fetcher._split_scopes(mock_items)
    config = fetcher._build_config("example", mock_program, scopes)

    tests = [
        ("split_scopes returns in/out keys",
         lambda: "in_scope" in scopes and "out_scope" in scopes),

        ("In-scope has 4 items (3 URL/wild + 1 mobile)",
         lambda: len(scopes["in_scope"]) == 4),

        ("Out-of-scope has 1 item",
         lambda: len(scopes["out_scope"]) == 1),

        ("Asset type mapping: WILDCARD → wildcard",
         lambda: scopes["in_scope"][0]["asset_type"] == "wildcard"),

        ("Asset type mapping: URL → url",
         lambda: scopes["in_scope"][1]["asset_type"] == "url"),

        ("Asset type mapping: ANDROID → mobile",
         lambda: any(s["asset_type"] == "mobile" for s in scopes["in_scope"])),

        ("Config has core_assets",
         lambda: len(config.get("core_assets", [])) >= 1),

        ("core_assets contain bounty-eligible domains",
         lambda: "*.example.com" in config["core_assets"]),

        ("non_core_assets contain non-bounty in-scope",
         lambda: "staging.example.com" in config["non_core_assets"]),

        ("forbidden_hosts contain out-of-scope",
         lambda: "internal.example.com" in config["forbidden_hosts"]),

        ("Config has handle key",
         lambda: config.get("handle") == "example"),

        ("Config has delay/rate_limit",
         lambda: config.get("delay") > 0 and config.get("rate_limit") > 0),

        ("URL scheme stripped from core_assets",
         lambda: all("://" not in a for a in config["core_assets"])),

        ("scope_raw preserved",
         lambda: "scope_raw" in config),

        ("No duplicate entries in core_assets",
         lambda: len(config["core_assets"]) == len(set(config["core_assets"]))),
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


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, os

    p = argparse.ArgumentParser(description="Fetch live H1 scope for a program")
    p.add_argument("--handle",   required=False, help="H1 program handle (e.g. gocardless)")
    p.add_argument("--user",     default=os.environ.get("H1_USERNAME",""), help="H1 username")
    p.add_argument("--token",    default=os.environ.get("H1_TOKEN",""),    help="H1 API token")
    p.add_argument("--save",     action="store_true", help="Save as YAML in configs/")
    p.add_argument("--no-cache", action="store_true", help="Bypass cache")
    p.add_argument("--test",     action="store_true", help="Run regression tests")
    args = p.parse_args()

    if args.test:
        rp, rf = run_regression_tests()
        import sys; sys.exit(0 if rf == 0 else 1)

    if not args.handle:
        p.error("--handle required (unless --test)")

    fetcher = H1ScopeFetcher(args.user, args.token)
    config  = fetcher.fetch(args.handle, use_cache=not args.no_cache)

    if args.save:
        path = fetcher.fetch_and_save_yaml(args.handle)
        print(f"Saved: {path}")
    else:
        import json
        print(json.dumps(config, indent=2))
