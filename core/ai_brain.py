#!/usr/bin/env python3
"""
AmonStrike — AI Brain
Real LLM reasoning engine. Uses local Ollama (free, no API key).
Falls back to cloud providers if configured.

The brain THINKS about every target — not templates, not signatures.
It reads HTTP responses, reasons about what's suspicious,
decides what to attack next, and writes H1 reports.

Setup (Kali):
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull llama3
    ollama serve &
"""

import json
import time
import requests
from pathlib import Path
from datetime import datetime

# ── Provider config ───────────────────────────────────────────

OLLAMA_URL  = "http://localhost:11434"
OLLAMA_MODEL = "llama3"          # llama3, mistral, codellama, phi3

# Optional cloud fallbacks (set env vars to enable)
import os, threading, concurrent.futures
GROQ_KEY    = os.environ.get("GROQ_API_KEY",   "")
GEMINI_KEY  = os.environ.get("GEMINI_API_KEY", "")
OPENAI_KEY  = os.environ.get("OPENAI_API_KEY", "")

GROQ_MODELS = [
    "llama3-70b-8192",
    "llama3-8b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]


class AIBrain:
    """
    Real AI reasoning for AmonStrike.
    Thinks like a senior pentester. Learns. Never stops improving.
    """

    SYSTEM_PROMPT = """You are an expert bug bounty hunter and penetration tester
with 10 years of experience. You have deep knowledge of:
- OWASP Top 10, API Security Top 10
- IDOR, SSRF, XSS, SQLi, Auth bypass, Business Logic, Race Conditions
- Zero-day chaining: combining multiple findings into critical vulnerabilities
- HackerOne submission standards and triage criteria

You analyze HTTP requests/responses and identify real security vulnerabilities.
You are precise, technical, and only report confirmed issues.
You think step by step. You never guess — you reason from evidence.
Output ONLY valid JSON when asked for structured data."""

    def __init__(self, model: str = OLLAMA_MODEL, verbose: bool = False):
        self.model   = model
        self.verbose = verbose
        self.provider = self._detect_provider()
        self.history  = []   # conversation memory
        print(f"[AIBrain] Provider: {self.provider} | Model: {self.model}")

    def _detect_provider(self) -> str:
        """Auto-detect best available LLM provider."""
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if models:
                    if not any(self.model in m for m in models):
                        self.model = models[0].split(":")[0]
                    return "ollama"
        except Exception:
            pass
        if GROQ_KEY:   return "groq"
        if GEMINI_KEY: return "gemini"
        if OPENAI_KEY: return "openai"
        return "mock"

    def _available_providers(self) -> list:
        """Return all providers currently reachable."""
        providers = []
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            if r.status_code == 200 and r.json().get("models"):
                providers.append("ollama")
        except Exception:
            pass
        if GROQ_KEY:   providers.append("groq")
        if GEMINI_KEY: providers.append("gemini")
        if OPENAI_KEY: providers.append("openai")
        return providers or ["mock"]

    def think(self, prompt: str, context: str = "",
              ensemble: bool = False) -> str:
        """
        Core reasoning. ensemble=True queries ALL providers in parallel
        and returns the most confident / longest response.
        """
        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        if ensemble:
            return self._ensemble_think(full_prompt)

        dispatch = {
            "ollama": self._call_ollama,
            "groq":   self._call_groq,
            "gemini": self._call_gemini,
            "openai": self._call_openai,
            "mock":   self._mock_response,
        }
        fn = dispatch.get(self.provider, self._mock_response)
        return fn(full_prompt)

    def _ensemble_think(self, prompt: str) -> str:
        """Query all available providers in parallel, return best answer."""
        providers = self._available_providers()
        if len(providers) == 1:
            return self.think(prompt)

        dispatch = {
            "ollama": self._call_ollama,
            "groq":   self._call_groq,
            "gemini": self._call_gemini,
            "openai": self._call_openai,
        }
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(dispatch[p], prompt): p
                       for p in providers if p in dispatch}
            for f in concurrent.futures.as_completed(futures, timeout=60):
                try:
                    r = f.result()
                    if r:
                        results.append(r)
                except Exception:
                    pass

        if not results:
            return self._mock_response(prompt)
        # Return longest non-empty response (most detailed)
        return max(results, key=len)

    def think_json(self, prompt: str, context: str = "") -> dict:
        """Think and parse result as JSON."""
        result = self.think(prompt + "\n\nRespond with valid JSON only.", context)
        try:
            # Extract JSON from response
            import re
            match = re.search(r'\{.*\}', result, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception:
            pass
        return {"raw": result, "parse_error": True}

    # ── Core intelligence methods ─────────────────────────────

    def analyze_response(self, request: dict, response: dict,
                         target_info: dict = None) -> dict:
        """
        Analyze an HTTP request/response pair.
        Returns: {is_vulnerable, vuln_type, confidence, next_steps, evidence}
        """
        prompt = f"""Analyze this HTTP exchange for security vulnerabilities.

TARGET: {target_info.get('url', 'unknown') if target_info else 'unknown'}
TECH STACK: {target_info.get('tech', []) if target_info else 'unknown'}

REQUEST:
Method: {request.get('method', 'GET')}
URL: {request.get('url', '')}
Headers: {json.dumps(request.get('headers', {}), indent=2)}
Body: {str(request.get('body', ''))[:500]}

RESPONSE:
Status: {response.get('status', 0)}
Headers: {json.dumps(response.get('headers', {}), indent=2)}
Body (first 800 chars): {str(response.get('body', ''))[:800]}

Analyze for:
1. IDOR / BOLA (insecure object references)
2. Authentication/authorization issues
3. Sensitive data exposure
4. Business logic flaws
5. Injection points (SQL, NoSQL, SSTI, command)
6. SSRF indicators
7. Unusual response patterns suggesting hidden functionality

Return JSON:
{{
  "is_vulnerable": true/false,
  "vuln_type": "string or null",
  "confidence": 0.0-1.0,
  "reasoning": "step by step analysis",
  "evidence": "specific response elements that indicate vulnerability",
  "next_steps": ["list of specific follow-up tests to confirm"],
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "h1_worthy": true/false
}}"""

        return self.think_json(prompt)

    def plan_attack(self, target: str, tech_stack: list,
                    endpoints: list, existing_findings: list) -> dict:
        """
        Given a target and what we know, plan the optimal attack strategy.
        Returns prioritized list of attack vectors.
        """
        prompt = f"""You are planning a bug bounty attack on this target.

TARGET: {target}
TECH STACK: {', '.join(tech_stack) if tech_stack else 'unknown'}
ENDPOINTS DISCOVERED: {len(endpoints)}
SAMPLE ENDPOINTS:
{chr(10).join(endpoints[:20])}

EXISTING FINDINGS:
{json.dumps(existing_findings[:5], indent=2) if existing_findings else 'none yet'}

Based on the tech stack and endpoints, what are the TOP 5 attack vectors
most likely to yield critical/high severity findings on HackerOne?

Consider:
- What vulnerabilities are common in this tech stack?
- Which endpoints look most promising for IDOR, auth bypass, injection?
- Are there any chains between the existing findings?
- What zero-day patterns could apply here?

Return JSON:
{{
  "top_attacks": [
    {{
      "rank": 1,
      "attack": "attack name",
      "target_endpoint": "specific endpoint or pattern",
      "reasoning": "why this is high priority",
      "payload_hint": "what to try",
      "expected_severity": "CRITICAL/HIGH/MEDIUM",
      "confidence": 0.0-1.0
    }}
  ],
  "chain_opportunities": ["describe any chains between findings"],
  "estimated_time_minutes": 0
}}"""

        return self.think_json(prompt)

    def generate_payload(self, vuln_type: str, endpoint: str,
                         context: str, previous_attempts: list) -> dict:
        """
        Generate intelligent, context-aware payloads.
        Not wordlists — actual reasoning about what will work HERE.
        """
        prompt = f"""Generate targeted payloads for this specific vulnerability.

VULNERABILITY TYPE: {vuln_type}
ENDPOINT: {endpoint}
CONTEXT: {context}
ALREADY TRIED (did not work):
{json.dumps(previous_attempts, indent=2) if previous_attempts else 'nothing yet'}

Generate 5 payloads specifically crafted for this endpoint and context.
Think about: encoding, context (HTML/JS/SQL/API), filters that might exist,
and what the application is likely doing with this input.

Return JSON:
{{
  "payloads": [
    {{
      "payload": "exact string to inject",
      "placement": "where to inject (parameter name, header, body field)",
      "encoding": "none/url/base64/html",
      "reasoning": "why this specific payload should work here",
      "detection_signal": "what in the response confirms success"
    }}
  ]
}}"""

        return self.think_json(prompt)

    def write_h1_report(self, finding: dict, target_info: dict) -> dict:
        """
        Write a professional HackerOne report from a raw finding.
        Quality that gets accepted and paid.
        """
        prompt = f"""Write a professional HackerOne bug report for this finding.

FINDING:
{json.dumps(finding, indent=2)}

TARGET PROGRAM: {target_info.get('program', 'unknown')}
TARGET URL: {target_info.get('url', 'unknown')}

Write a complete H1 report that:
1. Has a clear, specific title (not generic)
2. Step-by-step reproduction steps (numbered, exact)
3. Proof of impact (what data/action is exposed)
4. CVSS score reasoning
5. Professional remediation advice

Return JSON:
{{
  "title": "specific vulnerability title",
  "severity": "critical/high/medium/low",
  "cvss_score": 0.0,
  "cvss_vector": "CVSS:3.1/AV:N/...",
  "vulnerability_information": "full markdown report body",
  "steps_to_reproduce": ["step 1", "step 2", ...],
  "impact": "what an attacker can do with this",
  "remediation": "how to fix it",
  "weakness": "CWE number and name"
}}"""

        return self.think_json(prompt)

    def validate_finding(self, finding: dict, evidence: str) -> dict:
        """
        Act as a skeptical H1 triager. Is this real or false positive?
        """
        prompt = f"""You are a HackerOne triager evaluating a reported vulnerability.
Be skeptical. Many reports are false positives.

FINDING:
Title: {finding.get('title', '')}
Type: {finding.get('vuln_class', finding.get('module', ''))}
Severity claimed: {finding.get('severity', 'unknown')}
URL: {finding.get('url', '')}
Description: {finding.get('description', '')[:500]}

EVIDENCE:
{evidence[:800]}

Ask yourself:
1. Is the evidence conclusive or could this be normal behavior?
2. Is there actual security impact or just a theoretical issue?
3. Would H1 triage accept this?
4. Is this a known false positive pattern?

Return JSON:
{{
  "is_real": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "detailed analysis",
  "triage_verdict": "accepted/likely_accepted/needs_more_evidence/false_positive/informational",
  "suggested_severity": "critical/high/medium/low/info",
  "missing_evidence": ["what else would make this bulletproof"]
}}"""

        return self.think_json(prompt)

    def identify_tech_stack(self, headers: dict, body: str,
                            url: str) -> dict:
        """Fingerprint technology stack from HTTP response."""
        prompt = f"""Identify the complete technology stack from this HTTP response.

URL: {url}
RESPONSE HEADERS:
{json.dumps(headers, indent=2)}

RESPONSE BODY (first 500 chars):
{body[:500]}

Return JSON:
{{
  "tech_stack": ["list of detected technologies"],
  "framework": "primary framework (Django/Rails/Laravel/Spring/etc)",
  "language": "backend language",
  "database_hints": ["any database clues"],
  "cdn_waf": ["CDN or WAF detected"],
  "vulnerabilities_common_in_stack": ["vuln types common in this stack"],
  "attack_priority": ["ordered list of what to try first for this stack"]
}}"""

        return self.think_json(prompt)

    def chain_findings(self, findings: list, target: str) -> list:
        """
        Given a list of findings, identify zero-day chains.
        """
        if not findings:
            return []

        prompt = f"""You are analyzing confirmed security findings to identify
vulnerability chains that escalate to critical severity.

TARGET: {target}

CONFIRMED FINDINGS:
{json.dumps([{{
    'type': f.get('vuln_class', f.get('module','')),
    'title': f.get('title',''),
    'severity': f.get('severity',''),
    'url': f.get('url','')
}} for f in findings], indent=2)}

Identify ALL possible vulnerability chains where:
Finding A + Finding B (+ Finding C) = Critical Zero-Day

Return JSON:
{{
  "chains": [
    {{
      "name": "chain name",
      "findings_involved": ["finding title 1", "finding title 2"],
      "chain_description": "how they combine step by step",
      "final_impact": "what attacker achieves",
      "severity": "CRITICAL",
      "confidence": 0.0-1.0,
      "steps": ["step 1", "step 2", "step 3"]
    }}
  ]
}}"""

        result = self.think_json(prompt)
        return result.get("chains", [])

    # ── Provider implementations ──────────────────────────────

    def _call_ollama(self, prompt: str) -> str:
        try:
            r = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model":  self.model,
                    "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 2048},
                },
                timeout=120,
            )
            if r.status_code == 200:
                return r.json().get("response", "")
        except Exception as e:
            if self.verbose:
                print(f"[AIBrain] Ollama error: {e}")
        return ""

    def _call_groq(self, prompt: str, model: str = "") -> str:
        """Call Groq API. Auto-rotates models on rate limit."""
        models = [model] if model else GROQ_MODELS
        for m in models:
            try:
                r = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {GROQ_KEY}",
                             "Content-Type": "application/json"},
                    json={
                        "model": m,
                        "messages": [
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens":  2048,
                    },
                    timeout=30,
                )
                if r.status_code == 200:
                    return r.json()["choices"][0]["message"]["content"]
                if r.status_code == 429:
                    # Rate limited on this model — try next
                    time.sleep(1)
                    continue
            except Exception as e:
                if self.verbose:
                    print(f"[AIBrain] Groq/{m} error: {e}")
        return ""

    def _call_gemini(self, prompt: str) -> str:
        try:
            r = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-1.5-flash:generateContent?key={GEMINI_KEY}",
                json={"contents": [{"parts": [{"text":
                    f"{self.SYSTEM_PROMPT}\n\n{prompt}"}]}]},
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            if self.verbose:
                print(f"[AIBrain] Gemini error: {e}")
        return ""

    def _call_openai(self, prompt: str) -> str:
        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_KEY}"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.1,
                },
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            if self.verbose:
                print(f"[AIBrain] OpenAI error: {e}")
        return ""

    def _mock_response(self, prompt: str) -> str:
        """Deterministic mock when no LLM available (for testing)."""
        if "is_vulnerable" in prompt:
            return '{"is_vulnerable": false, "confidence": 0.5, "reasoning": "mock - no LLM", "severity": "INFO", "h1_worthy": false, "next_steps": [], "evidence": ""}'
        if "top_attacks" in prompt:
            return '{"top_attacks": [{"rank": 1, "attack": "IDOR", "target_endpoint": "/api/*", "reasoning": "mock", "payload_hint": "increment IDs", "expected_severity": "HIGH", "confidence": 0.7}], "chain_opportunities": [], "estimated_time_minutes": 30}'
        return '{"mock": true, "message": "Install Ollama for real AI reasoning"}'

    def status(self) -> dict:
        available = self._available_providers()
        return {
            "primary_provider": self.provider,
            "all_providers":    available,
            "ensemble_ready":   len(available) > 1,
            "model":            self.model,
            "ollama_url":       OLLAMA_URL,
            "groq":             bool(GROQ_KEY),
            "groq_models":      GROQ_MODELS if GROQ_KEY else [],
            "gemini":           bool(GEMINI_KEY),
            "openai":           bool(OPENAI_KEY),
        }


# ── Singleton for pipeline use ────────────────────────────────

_brain = None

def get_brain() -> AIBrain:
    global _brain
    if _brain is None:
        _brain = AIBrain()
    return _brain


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--status",  action="store_true")
    ap.add_argument("--think",   default="", help="Ask brain a question")
    ap.add_argument("--model",   default=OLLAMA_MODEL)
    ap.add_argument("--install", action="store_true",
                    help="Print Ollama install commands")
    args = ap.parse_args()

    if args.install:
        print("""
# Install Ollama on Kali Linux (free local AI):
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull llama3

# Optional: faster/smarter models
ollama pull mistral
ollama pull codellama
ollama pull phi3

# Free cloud (no install):
# Groq: https://console.groq.com → get free API key → export GROQ_API_KEY=...
# Gemini: https://aistudio.google.com → get free key → export GEMINI_API_KEY=...
""")
    elif args.status:
        brain = AIBrain(model=args.model)
        print(json.dumps(brain.status(), indent=2))
    elif args.think:
        brain = AIBrain(model=args.model, verbose=True)
        print(brain.think(args.think))
    else:
        brain = AIBrain(model=args.model)
        print(f"AIBrain ready | Provider: {brain.provider} | Model: {brain.model}")
        print("Run: python3 core/ai_brain.py --install")
