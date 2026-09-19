#!/usr/bin/env python3
"""
AmonStrike — Real-time Alert Engine
Fires Slack/Discord/Telegram webhooks on CRITICAL/HIGH findings.

Setup on Kali:
  export SLACK_WEBHOOK="https://hooks.slack.com/services/..."
  export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
  export TELEGRAM_BOT_TOKEN="..."
  export TELEGRAM_CHAT_ID="..."
"""
import os, json, requests

SLACK_WEBHOOK    = os.environ.get("SLACK_WEBHOOK", "")
DISCORD_WEBHOOK  = os.environ.get("DISCORD_WEBHOOK", "")
TG_TOKEN         = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT          = os.environ.get("TELEGRAM_CHAT_ID", "")

SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _slack(msg: str):
    if not SLACK_WEBHOOK:
        return
    try:
        requests.post(SLACK_WEBHOOK,
                      json={"text": msg}, timeout=8)
    except Exception:
        pass


def _discord(msg: str):
    if not DISCORD_WEBHOOK:
        return
    try:
        requests.post(DISCORD_WEBHOOK,
                      json={"content": msg[:2000]}, timeout=8)
    except Exception:
        pass


def _telegram(msg: str):
    if not TG_TOKEN or not TG_CHAT:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT, "text": msg[:4096], "parse_mode": "Markdown"},
            timeout=8,
        )
    except Exception:
        pass


def alert(finding: dict):
    """Send alert for a single finding to all configured channels."""
    sev   = finding.get("severity", "INFO").upper()
    if sev not in ("CRITICAL", "HIGH"):
        return

    emoji = SEV_EMOJI.get(sev, "⚪")
    score = finding.get("cvss_score", "")
    score_str = f" | CVSS {score}" if score else ""

    msg = (
        f"{emoji} *AmonStrike {sev}*{score_str}\n"
        f"*{finding.get('title','')[:80]}*\n"
        f"URL: {finding.get('url','')[:100]}\n"
        f"Module: {finding.get('module','')}\n"
        f"Evidence: {str(finding.get('evidence',''))[:200]}"
    )

    _slack(msg)
    _discord(msg)
    _telegram(msg)


def alert_batch(findings: list):
    """Alert on all critical/high findings."""
    for f in findings:
        alert(f)


def alert_text(text: str):
    """Send arbitrary text to all channels."""
    _slack(text)
    _discord(text)
    _telegram(text)
