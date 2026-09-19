#!/usr/bin/env python3
"""
AmonStrike — Deep Reasoning Engine
Implements chain-of-thought + Fable 5.1 narrative reasoning + consensus voting.

How it works:
  1. THINK step  — all models reason independently (parallel)
  2. VOTE step   — models vote on the conclusion
  3. VERIFY step — highest-confidence model re-checks the winner
  4. NARRATE step— Fable 5.1 builds the attack narrative (if available)

This mirrors how senior pentesters actually think:
  "What do I see? What does this mean? Is this exploitable? Tell the story."
"""
import os, json, re, time, threading
import concurrent.futures
import requests
from pathlib import Path
from datetime import datetime

# Provider config (all from env vars)
GROQ_KEY      = os.environ.get("GROQ_API_KEY",      "")
GEMINI_KEY    = os.environ.get("GEMINI_API_KEY",    "")
OPENAI_KEY    = os.environ.get("OPENAI_API_KEY",    "")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
NVIDIA_KEY    = os.environ.get("NVIDIA_API_KEY",    "")   # build.nvidia.com free key
OLLAMA_URL    = "http://localhost:11434"

# NVIDIA NIM API — OpenAI-compatible, free tier at build.nvidia.com
NVIDIA_NIM_URL  = "https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL    = "nvidia/llama-3.1-nemotron-70b-instruct"  # top-tier free model

GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

# ── Security-specialized system prompt ───────────────────────
SECURITY_SYSTEM = """You are AmonStrike, an elite bug bounty hunter AI with the following capabilities:

EXPERTISE:
- 10+ years bug bounty experience across HackerOne, Bugcrowd, Intigriti
- Deep knowledge: OWASP Top 10, API Security Top 10, OAuth, JWT, GraphQL, WebSockets
- Zero-day chaining: IDOR→ATO, SSRF→RCE, XSS→CSRF→Admin, JWT→Priv Esc
- Advanced techniques: HTTP request smuggling, race conditions, business logic
- CVSS scoring, HackerOne triage criteria, report writing

REASONING STYLE:
- Think step by step, like a detective building a case
- Distinguish real vulnerabilities from false positives rigorously
- Consider the IMPACT, not just the existence of a bug
- Only report what is CONFIRMED with evidence, not theoretical

OUTPUT FORMAT:
- Always return valid JSON when asked for structured data
- Use severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
- Include concrete evidence, not speculation
- Chain findings to identify escalation paths"""


# ── Fable 5.1 narrative reasoning prompt ─────────────────────
FABLE_NARRATIVE_PROMPT = """You are a master storyteller and security analyst.
For this security analysis, tell the story of what is happening:

1. THE SCENE: What is this application doing? What is its purpose?
2. THE ANOMALY: What unusual or suspicious behavior did you observe?
3. THE EXPLOIT: If this is vulnerable, tell the complete story of how an attacker would exploit it
4. THE IMPACT: What happens in the story when the attacker succeeds?
5. THE VERDICT: Is this a real vulnerability or a false alarm?

Use narrative reasoning — stories reveal truth that direct analysis misses.
Then extract your final security verdict in JSON."""


class ReasoningEngine:
    """
    Multi-model, chain-of-thought, consensus-based reasoning.
    The intelligence core of AmonStrike.
    """

    def __init__(self, verbose: bool = False):
        self.verbose   = verbose
        self._providers = self._detect_providers()
        print(f"[Reasoning] Active providers: {self._providers}")

    def _detect_providers(self) -> list:
        providers = []
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            if r.status_code == 200 and r.json().get("models"):
                providers.append("ollama")
        except Exception:
            pass
        if GROQ_KEY:      providers.append("groq")
        if NVIDIA_KEY:    providers.append("nvidia")  # Nemotron-70B via NIM
        if GEMINI_KEY:    providers.append("gemini")
        if OPENAI_KEY:    providers.append("openai")
        if ANTHROPIC_KEY: providers.append("fable")   # claude-fable-5-1
        return providers or ["mock"]

    # ── Core reasoning methods ────────────────────────────────

    def reason(self, prompt: str, context: str = "",
               use_cot: bool = True, consensus: bool = True) -> dict:
        """
        Full reasoning pipeline.
        Returns: {answer, confidence, reasoning_steps, consensus_score, provider_votes}
        """
        full_prompt = f"CONTEXT:\n{context}\n\nQUESTION:\n{prompt}" if context else prompt

        if use_cot:
            full_prompt = self._add_cot_scaffold(full_prompt)

        if consensus and len(self._providers) > 1:
            return self._consensus_reason(full_prompt)
        else:
            primary = self._providers[0]
            answer  = self._call(primary, full_prompt)
            return {
                "answer":          answer,
                "confidence":      0.7,
                "provider":        primary,
                "consensus_score": 1.0,
                "provider_votes":  {primary: answer},
            }

    def deep_analyze(self, request: dict, response: dict,
                     scan_context: str = "") -> dict:
        """
        Deep vulnerability analysis with Fable narrative reasoning.
        This is the most thorough analysis possible.
        """
        # Step 1: Direct technical analysis (all providers)
        tech_prompt = f"""Analyze this HTTP exchange for security vulnerabilities.

REQUEST:
Method: {request.get('method','GET')}
URL: {request.get('url','')}
Headers: {json.dumps(dict(list(request.get('headers',{}).items())[:10]))}
Body: {str(request.get('body',''))[:500]}

RESPONSE:
Status: {response.get('status',0)}
Headers: {json.dumps(dict(list(response.get('headers',{}).items())[:10]))}
Body: {str(response.get('body',''))[:800]}

SCAN CONTEXT (what we already know about this app):
{scan_context[:500] if scan_context else 'First analysis of this target'}

Analyze for: IDOR, auth bypass, injection, SSRF, XSS, business logic, info disclosure.

Return JSON:
{{
  "is_vulnerable": true/false,
  "vuln_type": "string or null",
  "confidence": 0.0-1.0,
  "reasoning": "step by step",
  "evidence": "specific response elements",
  "next_steps": ["follow-up tests"],
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "h1_worthy": true/false
}}"""

        # Step 2: Fable narrative reasoning (if available)
        fable_result = {}
        if "fable" in self._providers:
            fable_prompt = f"{FABLE_NARRATIVE_PROMPT}\n\nHTTP EXCHANGE:\n{tech_prompt}"
            fable_raw = self._call("fable", fable_prompt)
            fable_result = self._extract_json(fable_raw)

        # Step 3: Consensus from all providers
        consensus = self._consensus_reason(tech_prompt)

        # Step 4: Merge — fable narrative overrides if high confidence
        result = self._extract_json(consensus["answer"])
        if fable_result.get("is_vulnerable") is not None:
            # Fable gets 40% weight in final verdict
            tech_conf   = result.get("confidence", 0.5)
            fable_conf  = fable_result.get("confidence", 0.5)
            merged_conf = tech_conf * 0.6 + fable_conf * 0.4
            result["confidence"]       = round(merged_conf, 3)
            result["fable_narrative"]  = fable_result.get("reasoning","")
            # If fable disagrees strongly, flag for manual review
            if (result.get("is_vulnerable") != fable_result.get("is_vulnerable")
                    and fable_conf > 0.7):
                result["needs_manual_review"] = True
                result["fable_verdict"] = fable_result.get("is_vulnerable")

        result["consensus_score"] = consensus.get("consensus_score", 0.5)
        result["providers_agreed"] = consensus.get("providers_agreed", [])
        return result

    def verify_finding(self, finding: dict, evidence: str,
                       scan_context: str = "") -> dict:
        """
        3-stage verification:
        1. Skeptic agent — tries to prove it's a false positive
        2. Advocate agent — defends why it's real
        3. Judge agent — makes final call based on both arguments
        """
        finding_summary = (
            f"Title: {finding.get('title','')}\n"
            f"Type: {finding.get('module', finding.get('vuln_class',''))}\n"
            f"Severity: {finding.get('severity','')}\n"
            f"URL: {finding.get('url','')}\n"
            f"Description: {finding.get('description','')[:300]}\n"
            f"Evidence: {evidence[:500]}"
        )

        # Agent 1: Skeptic
        skeptic_prompt = f"""You are a skeptical security triager. Your job is to REJECT false positives.
Be harsh. Only accept findings with conclusive evidence.

FINDING TO EVALUATE:
{finding_summary}

SCAN CONTEXT:
{scan_context[:300]}

Is this a false positive? Find every reason why this might NOT be a real vulnerability.
Return JSON: {{"is_false_positive": true/false, "confidence": 0.0-1.0, "reasons": ["list of concerns"]}}"""

        # Agent 2: Advocate
        advocate_prompt = f"""You are a bug bounty hunter defending a finding.
Your job is to build the strongest case for why this IS a real vulnerability.

FINDING TO EVALUATE:
{finding_summary}

Build the case: what evidence confirms this is real? What is the actual security impact?
Return JSON: {{"is_real": true/false, "confidence": 0.0-1.0, "impact": "specific impact", "evidence_quality": "strong/medium/weak"}}"""

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_skeptic  = ex.submit(self._call_best, skeptic_prompt)
            f_advocate = ex.submit(self._call_best, advocate_prompt)
            skeptic_raw  = f_skeptic.result(timeout=30)
            advocate_raw = f_advocate.result(timeout=30)

        skeptic  = self._extract_json(skeptic_raw)
        advocate = self._extract_json(advocate_raw)

        # Agent 3: Judge
        judge_prompt = f"""You are the final judge on this security finding.

SKEPTIC argues: {json.dumps(skeptic)}
ADVOCATE argues: {json.dumps(advocate)}

ORIGINAL FINDING: {finding_summary[:300]}

Make the final verdict. Who has the stronger case?
Return JSON:
{{
  "is_real": true/false,
  "confidence": 0.0-1.0,
  "verdict": "accepted/likely_accepted/needs_more_evidence/false_positive",
  "reasoning": "why you ruled this way",
  "suggested_severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "missing_evidence": ["what would make this bulletproof"]
}}"""

        judge_raw = self._call_best(judge_prompt)
        verdict   = self._extract_json(judge_raw)

        verdict["skeptic_concerns"]   = skeptic.get("reasons", [])
        verdict["advocate_evidence"]  = advocate.get("impact","")
        verdict["evidence_quality"]   = advocate.get("evidence_quality","medium")
        return verdict

    def plan_next_attack(self, scan_context: str,
                         failed: list, succeeded: list) -> dict:
        """
        Real-time attack planning based on current context.
        Replaces static module lists with adaptive AI decisions.
        """
        prompt = f"""You are planning the NEXT attack step for a bug bounty scan.

CURRENT SCAN STATE:
{scan_context}

ATTACKS THAT FAILED: {json.dumps(failed[:10])}
ATTACKS THAT SUCCEEDED: {json.dumps(succeeded[:5])}

Based on what you know NOW, what is the single most valuable next attack?
Consider: what findings enable what chains? What hasn't been tried yet?
What is the highest-probability path to a CRITICAL finding?

Return JSON:
{{
  "next_action": "specific attack name",
  "target_endpoint": "which endpoint to attack",
  "reasoning": "why this is the best next step",
  "expected_severity": "CRITICAL/HIGH/MEDIUM",
  "probability": 0.0-1.0,
  "prerequisites": ["what must be true for this to work"],
  "chain_potential": "how this connects to other findings"
}}"""

        result = self._call_best(prompt)
        return self._extract_json(result)

    def generate_smart_payload(self, vuln_type: str, endpoint: str,
                                tech_stack: list, context: str,
                                failed_payloads: list) -> dict:
        """
        Generate context-aware payloads — not wordlists.
        AI reasons about this specific endpoint and what will work HERE.
        """
        prompt = f"""Generate targeted payloads for this specific vulnerability.

VULN TYPE: {vuln_type}
ENDPOINT: {endpoint}
TECH STACK: {', '.join(tech_stack) if tech_stack else 'unknown'}
CONTEXT: {context[:300]}
FAILED PAYLOADS (don't repeat): {json.dumps(failed_payloads[:10])}

Think about:
- What is the application doing with this input?
- What filters/sanitization is likely in place given the tech stack?
- What encoding/obfuscation bypasses the expected filters?
- What is the minimal payload that confirms the vulnerability?

Return JSON:
{{
  "payloads": [
    {{
      "payload": "exact string",
      "placement": "param name or location",
      "encoding": "none/url/base64/html",
      "reasoning": "why this works here",
      "success_signal": "what in response confirms success",
      "confidence": 0.0-1.0
    }}
  ],
  "approach": "overall strategy"
}}"""

        result = self._call_best(prompt)
        return self._extract_json(result)

    def write_report(self, finding: dict, scan_context: str) -> dict:
        """Write a professional H1 report that gets accepted and paid."""
        prompt = f"""Write a professional HackerOne bug bounty report.

FINDING:
{json.dumps(finding, indent=2)}

SCAN CONTEXT (supporting evidence):
{scan_context[:500]}

Requirements:
- Specific, non-generic title
- Exact numbered reproduction steps
- Concrete proof of impact (what data/action is exposed)
- Professional remediation advice
- CVSS 3.1 vector

Return JSON:
{{
  "title": "Specific vuln title with endpoint",
  "severity": "critical/high/medium/low",
  "cvss_score": 0.0,
  "cvss_vector": "CVSS:3.1/AV:N/...",
  "vulnerability_information": "Full markdown report body",
  "steps_to_reproduce": ["Step 1: ...", "Step 2: ..."],
  "impact": "Exact attacker capability",
  "remediation": "Specific fix",
  "weakness_id": 0,
  "weakness_name": "CWE name"
}}"""

        result = self._call_best(prompt)
        return self._extract_json(result)

    # ── Provider implementations ──────────────────────────────

    def _consensus_reason(self, prompt: str) -> dict:
        """Query all providers, extract JSON answers, vote on consensus."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self._call, p, prompt): p
                for p in self._providers[:4]
            }
            raw_results = {}
            for f in concurrent.futures.as_completed(futures, timeout=45):
                p = futures[f]
                try:
                    raw_results[p] = f.result()
                except Exception:
                    pass

        if not raw_results:
            return {"answer": "{}", "confidence": 0.0, "consensus_score": 0.0,
                    "providers_agreed": []}

        # Extract JSON from each
        parsed = {}
        for p, raw in raw_results.items():
            j = self._extract_json(raw)
            if j and not j.get("parse_error"):
                parsed[p] = j

        if not parsed:
            best = max(raw_results.values(), key=len)
            return {"answer": best, "confidence": 0.5, "consensus_score": 0.5,
                    "providers_agreed": list(raw_results.keys())}

        # Vote on key boolean fields
        votes   = {"is_vulnerable": [], "is_real": [], "h1_worthy": []}
        confs   = []
        for p, j in parsed.items():
            for key in votes:
                if key in j:
                    votes[key].append(j[key])
            if "confidence" in j:
                confs.append(float(j["confidence"]))

        consensus_score = 1.0
        agreed = list(parsed.keys())
        for key, vals in votes.items():
            if len(vals) >= 2:
                majority = sum(1 for v in vals if v) > len(vals) / 2
                agree_rate = sum(1 for v in vals if v == majority) / len(vals)
                consensus_score = min(consensus_score, agree_rate)

        avg_conf = sum(confs) / len(confs) if confs else 0.6
        # Boost confidence when providers agree
        if consensus_score > 0.8:
            avg_conf = min(0.99, avg_conf * 1.15)

        # Return the most detailed answer
        best_provider = max(parsed.keys(),
                            key=lambda p: len(json.dumps(parsed[p])))
        best_answer   = json.dumps(parsed[best_provider])

        return {
            "answer":           best_answer,
            "confidence":       round(avg_conf, 3),
            "consensus_score":  round(consensus_score, 3),
            "providers_agreed": agreed,
            "all_verdicts":     {p: j.get("is_vulnerable", j.get("is_real"))
                                 for p, j in parsed.items()},
        }

    def _call_best(self, prompt: str) -> str:
        """Call the best available provider."""
        for provider in self._providers:
            result = self._call(provider, prompt)
            if result:
                return result
        return "{}"

    def _call(self, provider: str, prompt: str) -> str:
        dispatch = {
            "ollama":  self._ollama,
            "groq":    self._groq,
            "nvidia":  self._nvidia,
            "gemini":  self._gemini,
            "openai":  self._openai,
            "fable":   self._fable,
            "mock":    self._mock,
        }
        fn = dispatch.get(provider, self._mock)
        try:
            return fn(prompt)
        except Exception as e:
            if self.verbose:
                print(f"[Reasoning] {provider} error: {e}")
            return ""

    def _ollama(self, prompt: str) -> str:
        # Use best available security model
        preferred = ["amonstrike-security","nemotron","nemotron-mini",
                     "llama3:70b","mixtral:8x7b","mistral:7b-instruct","llama3","llama2"]
        model = "llama3"
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            if r.status_code == 200:
                available = [m["name"] for m in r.json().get("models", [])]
                for pref in preferred:
                    if any(pref in a for a in available):
                        model = pref
                        break
                if not model and available:
                    model = available[0].split(":")[0]
        except Exception:
            pass

        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model":  model,
                "prompt": f"{SECURITY_SYSTEM}\n\n{prompt}",
                "stream": False,
                "options": {
                    "temperature": 0.05,   # very low — deterministic security analysis
                    "num_predict": 3000,
                    "top_p": 0.9,
                    "repeat_penalty": 1.1,
                },
            },
            timeout=120,
        )
        return r.json().get("response", "") if r.status_code == 200 else ""

    def _groq(self, prompt: str) -> str:
        for model in GROQ_MODELS:
            try:
                r = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {GROQ_KEY}",
                             "Content-Type": "application/json"},
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": SECURITY_SYSTEM},
                            {"role": "user",   "content": prompt},
                        ],
                        "temperature": 0.05,
                        "max_tokens":  3000,
                        "response_format": {"type": "json_object"},
                    },
                    timeout=30,
                )
                if r.status_code == 200:
                    return r.json()["choices"][0]["message"]["content"]
                if r.status_code == 429:
                    time.sleep(2)
                    continue
            except Exception:
                pass
        return ""

    def _gemini(self, prompt: str) -> str:
        try:
            r = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-1.5-flash:generateContent?key={GEMINI_KEY}",
                json={"contents": [{"parts": [{"text":
                    f"{SECURITY_SYSTEM}\n\n{prompt}"}]}],
                    "generationConfig": {"temperature": 0.05, "maxOutputTokens": 3000}},
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            pass
        return ""

    def _openai(self, prompt: str) -> str:
        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": SECURITY_SYSTEM},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.05,
                    "response_format": {"type": "json_object"},
                },
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass
        return ""

    def _fable(self, prompt: str) -> str:
        """Claude Fable 5.1 — narrative reasoning, best for nuanced analysis."""
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":         ANTHROPIC_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type":      "application/json",
                },
                json={
                    "model":      "claude-fable-5-1",
                    "max_tokens": 4000,
                    "system":     SECURITY_SYSTEM,
                    "messages":   [{"role": "user", "content": prompt}],
                },
                timeout=60,
            )
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
        except Exception as e:
            if self.verbose:
                print(f"[Reasoning] Fable error: {e}")
        return ""

    def _nvidia(self, prompt: str) -> str:
        """NVIDIA NIM — Nemotron-70B via build.nvidia.com (OpenAI-compatible, free tier)."""
        if not NVIDIA_KEY:
            return ""
        try:
            r = requests.post(
                f"{NVIDIA_NIM_URL}/chat/completions",
                headers={"Authorization": f"Bearer {NVIDIA_KEY}",
                         "Content-Type": "application/json"},
                json={
                    "model":       NVIDIA_MODEL,
                    "messages": [
                        {"role": "system", "content": SECURITY_SYSTEM},
                        {"role": "user",   "content": prompt},
                    ],
                    "temperature": 0.05,
                    "max_tokens":  4096,
                },
                timeout=45,
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            if self.verbose:
                print(f"[Reasoning] NVIDIA NIM error: {e}")
        return ""

    def _mock(self, prompt: str) -> str:
        return json.dumps({
            "is_vulnerable": False,
            "confidence":    0.3,
            "reasoning":     "mock — install Ollama or set GROQ_API_KEY",
            "severity":      "INFO",
            "h1_worthy":     False,
        })

    def _add_cot_scaffold(self, prompt: str) -> str:
        """Add chain-of-thought reasoning scaffold."""
        return (
            f"{prompt}\n\n"
            "Think step by step:\n"
            "STEP 1 - OBSERVE: What exactly do I see in the data?\n"
            "STEP 2 - HYPOTHESIZE: What vulnerability could this indicate?\n"
            "STEP 3 - EVALUATE: What evidence confirms or denies this hypothesis?\n"
            "STEP 4 - CONCLUDE: Is this exploitable? What is the real impact?\n"
            "STEP 5 - JSON: Now output the structured result.\n"
        )

    def _extract_json(self, text: str) -> dict:
        if not text:
            return {}
        try:
            # Try direct parse first
            return json.loads(text)
        except Exception:
            pass
        # Extract from markdown or mixed text
        for pattern in [r'```json\s*(\{.*?\})\s*```',
                        r'```\s*(\{.*?\})\s*```',
                        r'(\{[^{}]*\{[^{}]*\}[^{}]*\})',
                        r'(\{.*?\})',]:
            m = re.search(pattern, text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except Exception:
                    pass
        return {"raw": text[:500], "parse_error": True}

    def status(self) -> dict:
        return {
            "providers":      self._providers,
            "fable_ready":    "fable"  in self._providers,
            "nvidia_ready":   "nvidia" in self._providers,
            "consensus_ready": len(self._providers) > 1,
            "groq":           bool(GROQ_KEY),
            "nvidia":         bool(NVIDIA_KEY),
            "gemini":         bool(GEMINI_KEY),
            "anthropic":      bool(ANTHROPIC_KEY),
        }


# ── Singleton ─────────────────────────────────────────────────
_engine = None

def get_reasoning_engine() -> ReasoningEngine:
    global _engine
    if _engine is None:
        _engine = ReasoningEngine()
    return _engine


if __name__ == "__main__":
    engine = ReasoningEngine(verbose=True)
    print(json.dumps(engine.status(), indent=2))
