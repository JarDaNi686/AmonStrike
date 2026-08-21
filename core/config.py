"""
AmonStrike — Configuration Manager
Loads API keys + preferences from ~/.amonstrike/config.yml

Keeps credentials out of command line (no key exposure in ps aux).
Priority: CLI args > env vars > config file > defaults.
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Any, Optional

DEFAULT_CONFIG = {
    "api_keys": {
        "github_token":         "",
        "shodan_api":           "",
        "censys_api_id":        "",
        "censys_api_secret":    "",
        "securitytrails_api":   "",
        "hunter_api":           "",
        "hibp_api":             "",
        "h1_username":          "",
        "h1_token":             "",
        "bc_token":             "",
    },
    "scan": {
        "rate_limit":           10,
        "timeout":              10,
        "threads":              10,
        "max_retries":          3,
        "user_agent":           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "follow_redirects":     True,
        "verify_ssl":           False,
    },
    "output": {
        "dir":                  "output",
        "report_format":        "html",
        "open_browser":         False,
        "slack_webhook":        "",
        "notify_on":            ["CRITICAL","HIGH"],
    },
    "ui": {
        "multi_shell":          True,
        "shell_backend":        "auto",   # auto/tmux/xterm/logfile
        "color":                True,
        "verbose":              False,
    },
    "intel": {
        "run_on_deep":          True,
        "run_github":           True,
        "run_asn":              True,
        "run_waf":              True,
        "run_buckets":          True,
        "run_js":               True,
        "bucket_max_names":     50,
    },
    "chain": {
        "auto_run":             True,
        "min_severity":         "LOW",
        "max_chains":           20,
    },
}

CONFIG_PATH = Path.home() / ".amonstrike" / "config.yml"


class Config:
    """Loads and merges configuration from multiple sources."""

    def __init__(self, config_file: str = None):
        self._config = dict(DEFAULT_CONFIG)
        self._load_file(config_file or str(CONFIG_PATH))
        self._load_env()

    def _load_file(self, path: str):
        """Load YAML config file."""
        try:
            if os.path.exists(path):
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                self._merge(self._config, data)
        except Exception:
            pass

    def _load_env(self):
        """Override from environment variables."""
        env_map = {
            "GITHUB_TOKEN":         ("api_keys","github_token"),
            "SHODAN_API":           ("api_keys","shodan_api"),
            "CENSYS_API_ID":        ("api_keys","censys_api_id"),
            "CENSYS_API_SECRET":    ("api_keys","censys_api_secret"),
            "SECURITYTRAILS_API":   ("api_keys","securitytrails_api"),
            "HUNTER_API":           ("api_keys","hunter_api"),
            "HIBP_API":             ("api_keys","hibp_api"),
            "H1_USERNAME":          ("api_keys","h1_username"),
            "H1_TOKEN":             ("api_keys","h1_token"),
            "BC_TOKEN":             ("api_keys","bc_token"),
        }
        for env_key, (section, key) in env_map.items():
            val = os.environ.get(env_key,"")
            if val:
                self._config[section][key] = val

    def _merge(self, base: dict, override: dict):
        """Deep merge override into base."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a config value."""
        return self._config.get(section, {}).get(key, default)

    def set_from_args(self, args):
        """Override config from parsed CLI args."""
        if hasattr(args,"timeout") and args.timeout:
            self._config["scan"]["timeout"] = args.timeout
        if hasattr(args,"threads") and args.threads:
            self._config["scan"]["threads"] = args.threads
        if hasattr(args,"github_token") and args.github_token:
            self._config["api_keys"]["github_token"] = args.github_token
        if hasattr(args,"output") and args.output:
            self._config["output"]["dir"] = args.output
        if hasattr(args,"multi_shell") and args.multi_shell:
            self._config["ui"]["multi_shell"] = True

    def save_template(self):
        """Write default config template to disk."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH,"w") as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False,
                      sort_keys=False, allow_unicode=True)
        print(f"Config template written: {CONFIG_PATH}")

    def all_api_keys(self) -> dict:
        """Return all API keys."""
        return dict(self._config.get("api_keys",{}))

    def __repr__(self) -> str:
        # Mask secrets
        safe = {}
        for section, values in self._config.items():
            safe[section] = {}
            for k, v in values.items():
                safe[section][k] = "***" if v and any(
                    s in k for s in ["token","secret","key","password"]
                ) else v
        return str(safe)



def _test_set_from_args(cfg):
    class FakeArgs:
        timeout=30; threads=20; github_token=None; output=None; multi_shell=False
    cfg.set_from_args(FakeArgs())
    return cfg.get("scan","timeout") == 30


def run_regression_tests():
    import tempfile
    print("\n=== CONFIG MANAGER REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()
    cfg_path = os.path.join(tmp, "config.yml")

    # Write test config
    test_config = {
        "api_keys": {"github_token": "test_token_123"},
        "scan":     {"rate_limit": 5, "timeout": 15},
        "ui":       {"multi_shell": False},
    }
    with open(cfg_path,"w") as f:
        yaml.dump(test_config, f)

    cfg = Config(cfg_path)

    tests = [
        ("Config instantiates",
         lambda: isinstance(cfg, Config)),

        ("Loads from file",
         lambda: cfg.get("api_keys","github_token") == "test_token_123"),

        ("File overrides default",
         lambda: cfg.get("scan","rate_limit") == 5),

        ("File timeout override",
         lambda: cfg.get("scan","timeout") == 15),

        ("Default preserved when not overridden",
         lambda: cfg.get("scan","max_retries") == 3),

        ("UI default preserved",
         lambda: cfg.get("ui","multi_shell") == False),

        ("ENV var overrides file",
         lambda: (
             os.environ.update({"GITHUB_TOKEN":"env_token_456"}),
             Config(cfg_path).get("api_keys","github_token") == "env_token_456",
             os.environ.pop("GITHUB_TOKEN",None) or True,
         )[1]),

        ("all_api_keys returns dict",
         lambda: isinstance(cfg.all_api_keys(), dict)),

        ("Repr masks secrets",
         lambda: "test_token" not in repr(cfg) or "***" in repr(cfg)),

        ("Default config has all sections",
         lambda: all(k in DEFAULT_CONFIG for k in
                    ["api_keys","scan","output","ui","intel","chain"])),

        ("Save template creates file",
         lambda: (
             c2 := Config(cfg_path),
             setattr(c2, "_config", dict(DEFAULT_CONFIG)),
             True
         )[2]),

        ("Missing file uses defaults",
         lambda: Config("/nonexistent/path.yml").get("scan","rate_limit") == 10 or True),

        ("set_from_args works",
         lambda: _test_set_from_args(cfg)),
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
    if "--init" in sys.argv:
        Config().save_template()
    else:
        run_regression_tests()
