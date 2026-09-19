#!/usr/bin/env python3
"""
AmonStrike — Data Directory Initializer
Run once after git clone on Kali:
  python setup_data.py
"""
import os, json
from pathlib import Path

DIRS = [
    "data/sessions",
    "data/scope_cache",
    "data/screenshots",
    "output/autonomous",
    "output/orchestrator",
    "logs",
]

FILES = {
    "data/findings.jsonl":          "",
    "data/autonomous_log.jsonl":    "",
    "data/submitted_reports.jsonl": "",
    "data/completed_targets.json":  "[]",
    "data/amonstrike.log":          "",
    "data/neural_kb.json": json.dumps({
        "version": 1,
        "patterns": [],
        "last_updated": ""
    }, indent=2),
}

ENV_VARS = {
    "GROQ_API_KEY":   "your_groq_api_key",
    "H1_USERNAME":    "your_h1_username",
    "H1_API_TOKEN":   "your_h1_api_token",
    "SLACK_WEBHOOK":  "",
    "DISCORD_WEBHOOK":"",
    "TELEGRAM_BOT_TOKEN": "",
    "TELEGRAM_CHAT_ID":   "",
}

def main():
    print("AmonStrike — Data Init")
    print("=" * 40)

    # Create directories
    for d in DIRS:
        Path(d).mkdir(parents=True, exist_ok=True)
        print(f"  [+] dir: {d}")

    # Create files
    for f, content in FILES.items():
        p = Path(f)
        if not p.exists():
            p.write_text(content)
            print(f"  [+] file: {f}")
        else:
            print(f"  [=] exists: {f}")

    # Check env vars
    print("\n  Environment variables:")
    missing = []
    for var, hint in ENV_VARS.items():
        val = os.environ.get(var, "")
        if val:
            print(f"  [✓] {var}")
        else:
            print(f"  [✗] {var} — not set")
            if hint and var not in ("SLACK_WEBHOOK","DISCORD_WEBHOOK","TELEGRAM_BOT_TOKEN","TELEGRAM_CHAT_ID"):
                missing.append(var)

    if missing:
        print(f"\n  REQUIRED: set these in ~/.bashrc:")
        for var in missing:
            print(f"    export {var}=\"{ENV_VARS[var]}\"")
        print(f"    source ~/.bashrc")
    else:
        print("\n  All required env vars set.")

    print("\n  Done. Run: python core/autonomous_engine.py --program <handle>")

if __name__ == "__main__":
    main()
