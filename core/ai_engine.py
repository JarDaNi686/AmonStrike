#!/usr/bin/env python3
"""
AmonStrike — 7-Layer AI Engine
================================
Integrates all 7 AI paradigms for penetration testing.

Layer 1: Classical AI    — Expert system, rule engine, decision trees
Layer 2: ML             — Anomaly detection, response classification
Layer 3: Neural Network  — Pattern recognition on HTTP responses
Layer 4: Deep Learning   — Transformer embeddings via Ollama
Layer 5: Generative AI   — LLM payload generation, report writing
Layer 6: Agentic AI      — Autonomous tool selection, reflection loop
Layer 7: AGI (Aspirational) — Self-improving meta-learner

Usage:
    from core.ai_engine import AmonStrikeAI
    ai = AmonStrikeAI()
    decision = ai.analyze(response, context)
"""

import re, json, time, math, hashlib, pickle
import requests, urllib3
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque

urllib3.disable_warnings()

MEMORY_PATH = Path.home() / ".amonstrike" / "ai_memory.pkl"


# ══════════════════════════════════════════════════════════════
# LAYER 1: CLASSICAL AI — Expert System + Rule Engine
# ══════════════════════════════════════════════════════════════

class ExpertSystem:
    """
    Rule-based expert system for vulnerability validation.
    Mimics human security expert knowledge encoded as rules.
    Each rule: condition → conclusion + confidence + action
    """

    RULES = [
        # SQLi rules
        {"id":"sqli_1","if": lambda r,c: any(e in r.get("body","") for e in
            ["SQL syntax","mysql_fetch","ORA-","pg_query","sqlite3.OperationalError"]),
         "then": "sqli_confirmed", "confidence": 0.95,
         "severity": "CRITICAL", "action": "extract_db"},

        {"id":"sqli_2","if": lambda r,c: r.get("delay",0) >= 4.0,
         "then": "sqli_time_based", "confidence": 0.90,
         "severity": "CRITICAL", "action": "extract_db"},

        # SSRF rules
        {"id":"ssrf_1","if": lambda r,c: any(k in r.get("body","") for k in
            ["ami-id","instance-id","AccessKeyId","serviceAccounts","local-ipv4"]),
         "then": "ssrf_cloud_metadata", "confidence": 0.98,
         "severity": "CRITICAL", "action": "pivot_internal"},

        {"id":"ssrf_2","if": lambda r,c: any(k in r.get("body","") for k in
            ["<!DOCTYPE","<html","<title"]) and r.get("module") == "ssrf",
         "then": "ssrf_false_positive", "confidence": 0.95,
         "severity": "NONE", "action": "discard"},

        # IDOR rules
        {"id":"idor_1","if": lambda r,c:
            any(f in r.get("body","").lower() for f in
                ["email_address","full_name","phone","uuid","api_key"]) and
            r.get("status_code") == 200,
         "then": "idor_pii_exposed", "confidence": 0.85,
         "severity": "HIGH", "action": "enumerate_ids"},

        {"id":"idor_2","if": lambda r,c:
            r.get("module") == "idor" and
            all(tag in r.get("body","") for tag in ["<!DOCTYPE","<html","og:title"]) and
            not any(f in r.get("body","").lower() for f in ["email","phone","password"]),
         "then": "idor_false_positive", "confidence": 0.93,
         "severity": "NONE", "action": "discard"},

        # RCE rules
        {"id":"rce_1","if": lambda r,c:
            bool(re.search(r'uid=\d+\(\w+\)\s+gid=\d+', r.get("body",""))),
         "then": "rce_confirmed", "confidence": 0.99,
         "severity": "CRITICAL", "action": "escalate"},

        {"id":"rce_2","if": lambda r,c:
            "uid=" in r.get("body","") and
            not re.search(r'uid=\d+\(\w+\)', r.get("body","")),
         "then": "rce_false_positive", "confidence": 0.85,
         "severity": "NONE", "action": "discard"},

        # XSS rules
        {"id":"xss_1","if": lambda r,c:
            c.get("payload","") in r.get("body","") and
            c.get("payload","").startswith("<"),
         "then": "xss_reflected", "confidence": 0.88,
         "severity": "HIGH", "action": "check_csp"},

        # Auth bypass
        {"id":"auth_1","if": lambda r,c:
            r.get("status_code") == 200 and
            c.get("authenticated") == False and
            any(k in r.get("body","").lower() for k in
                ["admin","dashboard","user","profile"]) and
            len(r.get("body","")) > 500,
         "then": "auth_bypass", "confidence": 0.80,
         "severity": "CRITICAL", "action": "escalate"},

        # Information disclosure
        {"id":"info_1","if": lambda r,c:
            any(k in r.get("body","") for k in
                ["stack trace","Traceback","NullPointerException","at java."]),
         "then": "stack_trace_disclosed", "confidence": 0.92,
         "severity": "MEDIUM", "action": "analyze_stack"},

        # Rate limit valid
        {"id":"rate_1","if": lambda r,c:
            r.get("http_200_count",0) >= 10 and
            r.get("http_429_count",0) == 0,
         "then": "rate_limit_absent", "confidence": 0.87,
         "severity": "MEDIUM", "action": "report"},
    ]

    def __init__(self):
        self.fired_rules = []

    def evaluate(self, response_data: dict, context: dict) -> dict:
        """Run all rules. Return conclusion with highest confidence."""
        conclusions = []
        for rule in self.RULES:
            try:
                if rule["if"](response_data, context):
                    conclusions.append({
                        "rule_id":    rule["id"],
                        "conclusion": rule["then"],
                        "confidence": rule["confidence"],
                        "severity":   rule["severity"],
                        "action":     rule["action"],
                    })
                    self.fired_rules.append(rule["id"])
            except Exception:
                pass

        if not conclusions:
            return {"conclusion": "inconclusive", "confidence": 0.0, "severity": "NONE"}

        # Return highest confidence conclusion
        best = max(conclusions, key=lambda x: x["confidence"])
        return best

    def is_false_positive(self, response_data: dict, context: dict) -> bool:
        result = self.evaluate(response_data, context)
        return result.get("severity") == "NONE"


# ══════════════════════════════════════════════════════════════
# LAYER 2: ML — Anomaly Detection + Response Classifier
# ══════════════════════════════════════════════════════════════

class ResponseFeatureExtractor:
    """Extract numerical features from HTTP responses for ML."""

    VULN_KEYWORDS = [
        "error","exception","sql","syntax","database","warning",
        "stack","trace","admin","password","secret","token","key",
        "unauthorized","forbidden","internal","debug","version",
    ]

    def extract(self, response_body: str, headers: dict,
                status_code: int) -> list:
        body = response_body.lower()
        return [
            # Status code features
            1.0 if status_code == 200 else 0.0,
            1.0 if status_code in [500, 503] else 0.0,
            1.0 if status_code in [403, 401] else 0.0,

            # Size features (normalized)
            min(len(response_body) / 100000.0, 1.0),
            min(response_body.count("\n") / 1000.0, 1.0),

            # Content type
            1.0 if "json" in headers.get("content-type","") else 0.0,
            1.0 if "html" in headers.get("content-type","") else 0.0,
            1.0 if "xml"  in headers.get("content-type","") else 0.0,

            # Keyword presence (vulnerability indicators)
            *[1.0 if kw in body else 0.0 for kw in self.VULN_KEYWORDS],

            # Security headers
            1.0 if "x-frame-options"        in headers else 0.0,
            1.0 if "content-security-policy" in headers else 0.0,
            1.0 if "x-xss-protection"        in headers else 0.0,
            1.0 if "strict-transport-security" in headers else 0.0,

            # Response structure
            1.0 if '{"error"' in response_body    else 0.0,
            1.0 if '"message"' in response_body    else 0.0,
            1.0 if "traceback" in body             else 0.0,
            1.0 if "exception" in body             else 0.0,
        ]


class AnomalyDetector:
    """
    ML Layer: Unsupervised anomaly detection using statistical methods.
    Detects responses that deviate from baseline — no training data needed.
    Uses: z-score normalization, isolation-style scoring.
    """

    def __init__(self):
        self.baseline    = {}
        self.n_observed  = 0
        self.feature_extractor = ResponseFeatureExtractor()

    def update_baseline(self, features: list):
        """Online learning — update baseline with each response."""
        if not self.baseline:
            self.baseline = {
                "mean": list(features),
                "m2":   [0.0] * len(features),
                "n":    1,
            }
            return

        n = self.baseline["n"] + 1
        for i, x in enumerate(features):
            old_mean = self.baseline["mean"][i]
            new_mean = old_mean + (x - old_mean) / n
            self.baseline["m2"][i] += (x - old_mean) * (x - new_mean)
            self.baseline["mean"][i] = new_mean
        self.baseline["n"] = n
        self.n_observed += 1

    def anomaly_score(self, features: list) -> float:
        """
        Score 0-1. Higher = more anomalous.
        Uses Welford's online variance for stability.
        """
        if not self.baseline or self.baseline["n"] < 5:
            return 0.5  # not enough data

        scores = []
        n = self.baseline["n"]
        for i, x in enumerate(features):
            mean = self.baseline["mean"][i]
            if n > 1:
                var = self.baseline["m2"][i] / (n - 1)
                std = math.sqrt(var) if var > 0 else 0.001
                z   = abs(x - mean) / std
                # Sigmoid transform z-score to 0-1
                score = 1.0 / (1.0 + math.exp(-z + 2.0))
            else:
                score = 0.5
            scores.append(score)

        return sum(scores) / len(scores) if scores else 0.5

    def is_anomalous(self, body: str, headers: dict,
                     status: int, threshold: float = 0.72) -> tuple:
        features = self.feature_extractor.extract(body, headers, status)
        self.update_baseline(features)
        score = self.anomaly_score(features)
        return score >= threshold, score


# ══════════════════════════════════════════════════════════════
# LAYER 3: NEURAL NETWORK — Response Pattern Classifier
# ══════════════════════════════════════════════════════════════

class NeuralClassifier:
    """
    3-layer feedforward neural network for vulnerability classification.
    No external dependencies — pure numpy-free implementation.
    Trained online from scan results.

    Input:  feature vector (from ResponseFeatureExtractor)
    Output: vulnerability probability [0,1]
    """

    def __init__(self, input_size: int = 37, hidden_size: int = 16):
        self.input_size  = input_size
        self.hidden_size = hidden_size

        # Xavier initialization
        limit_1 = math.sqrt(6.0 / (input_size + hidden_size))
        limit_2 = math.sqrt(6.0 / (hidden_size + 1))

        # Weights as flat lists (no numpy)
        self.W1 = [[self._rand(-limit_1, limit_1)
                    for _ in range(input_size)]
                   for _ in range(hidden_size)]
        self.b1 = [0.0] * hidden_size

        self.W2 = [self._rand(-limit_2, limit_2)
                   for _ in range(hidden_size)]
        self.b2 = 0.0

        self.lr  = 0.01
        self.trained = 0

    @staticmethod
    def _rand(lo: float, hi: float) -> float:
        import random
        return random.uniform(lo, hi)

    @staticmethod
    def _relu(x: float) -> float:
        return max(0.0, x)

    @staticmethod
    def _relu_d(x: float) -> float:
        return 1.0 if x > 0 else 0.0

    @staticmethod
    def _sigmoid(x: float) -> float:
        x = max(-500.0, min(500.0, x))
        return 1.0 / (1.0 + math.exp(-x))

    def _forward(self, x: list) -> tuple:
        """Forward pass. Returns (hidden activations, output)."""
        # Layer 1
        z1 = [sum(self.W1[j][i] * x[i]
                  for i in range(min(len(x), self.input_size)))
              + self.b1[j]
              for j in range(self.hidden_size)]
        h = [self._relu(v) for v in z1]

        # Layer 2
        z2 = sum(self.W2[j] * h[j]
                 for j in range(self.hidden_size)) + self.b2
        out = self._sigmoid(z2)

        return z1, h, out

    def predict(self, features: list) -> float:
        """Predict vulnerability probability."""
        # Pad or truncate to expected size
        x = (features + [0.0] * self.input_size)[:self.input_size]
        _, _, out = self._forward(x)
        return out

    def train(self, features: list, label: float):
        """
        Online learning — train one sample at a time.
        label: 1.0 = vulnerable, 0.0 = safe
        """
        x  = (features + [0.0] * self.input_size)[:self.input_size]
        z1, h, out = self._forward(x)

        # Backprop
        d_out = out - label

        # Update W2, b2
        for j in range(self.hidden_size):
            self.W2[j] -= self.lr * d_out * h[j]
        self.b2 -= self.lr * d_out

        # Update W1, b1
        for j in range(self.hidden_size):
            d_h = d_out * self.W2[j] * self._relu_d(z1[j])
            for i in range(self.input_size):
                self.W1[j][i] -= self.lr * d_h * x[i]
            self.b1[j] -= self.lr * d_h

        self.trained += 1

    def to_dict(self) -> dict:
        return {"W1": self.W1, "b1": self.b1,
                "W2": self.W2, "b2": self.b2, "trained": self.trained}

    def from_dict(self, d: dict):
        self.W1 = d["W1"]; self.b1 = d["b1"]
        self.W2 = d["W2"]; self.b2 = d["b2"]
        self.trained = d.get("trained", 0)


# ══════════════════════════════════════════════════════════════
# LAYER 4: DEEP LEARNING — Transformer Embeddings via Ollama
# ══════════════════════════════════════════════════════════════

class DeepLearningLayer:
    """
    Uses transformer model (via Ollama API) for:
    - Semantic similarity between responses
    - Understanding API structure from natural language
    - Finding related vulnerabilities across different endpoints
    """

    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.model      = "deepseek-r1:14b"  # 32GB RAM
        self.cache      = {}

    def embed(self, text: str) -> list:
        """Get embedding vector for text."""
        cache_key = hashlib.md5(text[:500].encode()).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]
        try:
            r = requests.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": self.model, "prompt": text[:1000]},
                timeout=15
            )
            if r.status_code == 200:
                embedding = r.json().get("embedding", [])
                self.cache[cache_key] = embedding
                return embedding
        except Exception:
            pass
        return []

    def cosine_similarity(self, v1: list, v2: list) -> float:
        """Cosine similarity between two vectors."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot   = sum(a * b for a, b in zip(v1, v2))
        mag1  = math.sqrt(sum(a * a for a in v1))
        mag2  = math.sqrt(sum(b * b for b in v2))
        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    def find_similar_findings(self, new_finding: dict,
                               past_findings: list) -> list:
        """
        Find semantically similar past findings.
        Enables: 'this looks like an IDOR we found before on similar tech'
        """
        if not past_findings:
            return []
        new_emb = self.embed(new_finding.get("title","") + " " +
                             new_finding.get("evidence","")[:200])
        if not new_emb:
            return []

        similar = []
        for pf in past_findings[-50:]:
            past_emb = self.embed(pf.get("title","") + " " +
                                  pf.get("evidence","")[:200])
            if past_emb:
                sim = self.cosine_similarity(new_emb, past_emb)
                if sim > 0.8:
                    similar.append({"finding": pf, "similarity": sim})

        return sorted(similar, key=lambda x: x["similarity"], reverse=True)[:3]

    def understand_api_structure(self, api_text: str) -> dict:
        """
        Use transformer reasoning to understand API structure.
        Input: raw API response text or endpoint description
        Output: structured understanding
        """
        try:
            r = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model":  self.model,
                    "prompt": (
                        f"Analyze this API response and identify:\n"
                        f"1. What data objects it returns\n"
                        f"2. Any ID fields that could be enumerated\n"
                        f"3. Any sensitive PII fields\n"
                        f"4. Possible IDOR vectors\n\n"
                        f"Response text:\n{api_text[:1000]}\n\n"
                        f"Return JSON only."
                    ),
                    "stream": False,
                },
                timeout=30
            )
            if r.status_code == 200:
                text = r.json().get("response", "")
                m = re.search(r'\{.*\}', text, re.DOTALL)
                if m:
                    return json.loads(m.group())
        except Exception:
            pass
        return {}


# ══════════════════════════════════════════════════════════════
# LAYER 5: GENERATIVE AI — LLM Payload Generation
# ══════════════════════════════════════════════════════════════

class GenerativeAI:
    """
    Generative AI for:
    - Novel payload generation based on target context
    - Report writing
    - Attack strategy generation
    - Bypass generation when blocked
    """

    def __init__(self, ollama_url: str = "http://localhost:11434",
                 api_key: str = ""):
        self.ollama_url = ollama_url
        self.api_key    = api_key
        self.model      = "deepseek-r1:14b"

    def _ask_ollama(self, prompt: str) -> str:
        try:
            r = requests.post(
                f"{self.ollama_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=60
            )
            if r.status_code == 200:
                return r.json().get("response", "")
        except Exception:
            pass
        return ""

    def _ask_claude(self, prompt: str) -> str:
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"Content-Type": "application/json"},
                json={
                    "model":      "claude-sonnet-4-6",
                    "max_tokens": 1000,
                    "messages":   [{"role": "user", "content": prompt}],
                },
                timeout=30
            )
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
        except Exception:
            pass
        return ""

    def generate_payloads(self, vuln_type: str, tech_stack: list,
                          waf: str, context: str) -> list:
        """Generate targeted payloads based on tech stack and WAF."""
        prompt = (
            f"You are an expert pentester.\n"
            f"Generate 5 unique {vuln_type} payloads for:\n"
            f"Tech: {tech_stack}\n"
            f"WAF: {waf or 'none'}\n"
            f"Context: {context[:200]}\n\n"
            f"Return JSON: {{\"payloads\": [\"p1\", \"p2\", \"p3\", \"p4\", \"p5\"]}}"
        )
        response = self._ask_ollama(prompt) or self._ask_claude(prompt)
        try:
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m:
                return json.loads(m.group()).get("payloads", [])
        except Exception:
            pass
        return []

    def generate_bypass(self, blocked_payload: str, waf_type: str,
                        tech: str) -> list:
        """When a payload is blocked, generate bypass variants."""
        prompt = (
            f"WAF type: {waf_type}\n"
            f"Tech: {tech}\n"
            f"Blocked payload: {blocked_payload}\n\n"
            f"Generate 3 bypass variants that evade this WAF.\n"
            f"Return JSON: {{\"bypasses\": [\"b1\", \"b2\", \"b3\"]}}"
        )
        response = self._ask_ollama(prompt) or self._ask_claude(prompt)
        try:
            m = re.search(r'\{.*\}', response, re.DOTALL)
            if m:
                return json.loads(m.group()).get("bypasses", [])
        except Exception:
            pass
        return []

    def write_h1_report(self, finding: dict) -> str:
        """Write a professional HackerOne bug report."""
        prompt = (
            f"Write a professional HackerOne bug bounty report.\n\n"
            f"Finding:\n{json.dumps(finding, default=str)[:800]}\n\n"
            f"Format:\n"
            f"## Summary\n[2-3 sentences]\n\n"
            f"## Steps to Reproduce\n[numbered]\n\n"
            f"## Proof of Concept\n```bash\n[curl command]\n```\n\n"
            f"## Impact\n[business impact]\n\n"
            f"## Severity\n{finding.get('severity','HIGH')}\n"
        )
        return self._ask_ollama(prompt) or self._ask_claude(prompt)


# ══════════════════════════════════════════════════════════════
# LAYER 6: AGENTIC AI — Autonomous Tool Selection & Reflection
# ══════════════════════════════════════════════════════════════

class AgenticLayer:
    """
    Autonomous agent that:
    - Selects tools based on current state
    - Reflects on results before reporting
    - Adapts strategy based on findings
    - Chains discoveries into attack sequences
    """

    def __init__(self, generative: GenerativeAI, expert: ExpertSystem):
        self.gen    = generative
        self.expert = expert
        self.memory = deque(maxlen=100)  # short-term memory

    def decide_next_action(self, state: dict) -> dict:
        """
        Given current state, decide what to do next.
        State: {findings, tech, waf, endpoints_tested, blocked}
        """
        findings    = state.get("findings", [])
        tech        = state.get("tech", [])
        waf         = state.get("waf", "")
        blocked     = state.get("blocked", [])

        # Reactive rules (fastest — no LLM needed)
        if any(f.get("module") == "ssrf" for f in findings):
            return {"action": "pivot_internal",
                    "reason": "SSRF found — probe internal network",
                    "priority": 1}

        if any(f.get("module") == "sqli" for f in findings):
            return {"action": "extract_database",
                    "reason": "SQLi found — extract credentials",
                    "priority": 1}

        if waf and len(blocked) > 3:
            return {"action": "waf_bypass",
                    "reason": f"WAF blocking {len(blocked)} payloads",
                    "priority": 2}

        # Default: continue systematic testing
        tested_modules = {f.get("module") for f in findings}
        priority_order = ["idor","ssrf","sqli","xss","cors",
                         "auth","jwt_deep","business_logic"]
        for mod in priority_order:
            if mod not in tested_modules:
                return {"action": f"run_{mod}",
                        "reason": f"{mod} not yet tested",
                        "priority": 3}

        return {"action": "complete", "reason": "All priority modules tested"}

    def reflect(self, finding: dict, response_data: dict) -> dict:
        """
        Reflect on a finding before reporting.
        Reduces false positives through self-questioning.
        """
        questions = [
            "Is the evidence real server data or just the payload echoed back?",
            "Could this be a false positive from error handling?",
            "Does the evidence prove actual vulnerability or just potential?",
        ]

        # Expert system evaluation
        expert_result = self.expert.evaluate(response_data, finding)
        if expert_result.get("severity") == "NONE":
            return {"verdict": "false_positive",
                    "confidence": expert_result["confidence"],
                    "reason": expert_result["conclusion"]}

        # Evidence quality check
        evidence = finding.get("evidence", "")
        if len(evidence) < 20:
            return {"verdict": "insufficient_evidence",
                    "confidence": 0.3, "reason": "Too little evidence"}

        # Remember this reflection
        self.memory.append({
            "finding": finding.get("title", ""),
            "verdict": "confirmed",
            "time": datetime.now().isoformat(),
        })

        return {"verdict": "confirmed",
                "confidence": expert_result.get("confidence", 0.75),
                "reason": "Expert system validated + sufficient evidence"}

    def chain_findings(self, findings: list) -> list:
        """Identify attack chains — multiple findings → higher impact."""
        chains   = []
        modules  = {f.get("module") for f in findings}

        chain_rules = [
            ({"idor","cors"},        "IDOR+CORS → Account Takeover", "CRITICAL", 10000),
            ({"sqli","auth"},        "SQLi+Auth → Full DB Access",   "CRITICAL",  8000),
            ({"ssrf","idor"},        "SSRF+IDOR → Internal Pivot",   "CRITICAL",  6000),
            ({"xss","csrf"},         "XSS+CSRF  → Account Takeover", "HIGH",      3000),
            ({"lfi","command_injection"}, "LFI→RCE Chain",           "CRITICAL", 12000),
        ]

        for required_modules, name, severity, bounty in chain_rules:
            if required_modules.issubset(modules):
                chains.append({
                    "name":           name,
                    "severity":       severity,
                    "bounty_estimate":bounty,
                    "modules":        list(required_modules),
                    "description":    f"Combined attack: {name}",
                })

        return chains


# ══════════════════════════════════════════════════════════════
# LAYER 7: AGI LAYER — Self-Improving Meta-Learner
# ══════════════════════════════════════════════════════════════

class AGILayer:
    """
    Self-improving meta-learning system.
    Learns WHAT WORKS across scans and improves automatically.

    Note: True AGI doesn't exist. This implements the closest
    practical approximation: a system that:
    - Learns from every scan without human intervention
    - Adapts strategy based on past performance
    - Generates novel hypotheses from observed patterns
    - Improves accuracy over time through feedback loops
    """

    def __init__(self, memory_path: Path = MEMORY_PATH):
        self.memory_path = memory_path
        self.memory      = self._load()
        self.session_data = []

    def observe(self, event: str, outcome: str, context: dict):
        """Record observation for learning."""
        self.session_data.append({
            "event":   event,
            "outcome": outcome,
            "context": {k: str(v)[:100] for k, v in context.items()},
            "time":    time.time(),
        })

    def learn_from_session(self, findings: list, target: str, tech: list):
        """
        After each scan: update knowledge base.
        Learns: what modules work on what tech stacks.
        """
        for f in findings:
            if f.get("severity") not in ["CRITICAL", "HIGH"]:
                continue
            module = f.get("module", "")
            key    = f"tech_{':'.join(sorted(tech[:3]))}"

            self.memory.setdefault("module_success", {})
            self.memory["module_success"].setdefault(key, {})
            self.memory["module_success"][key][module] = \
                self.memory["module_success"][key].get(module, 0) + 1

        self.memory.setdefault("scan_count", 0)
        self.memory["scan_count"] += 1
        self._save()

    def get_optimized_module_order(self, tech: list) -> list:
        """
        Return modules in order of historical success for this tech stack.
        Gets smarter with each scan.
        """
        key = f"tech_{':'.join(sorted(tech[:3]))}"
        success = self.memory.get("module_success", {}).get(key, {})

        default_order = [
            "idor", "ssrf", "sqli", "xss", "cors",
            "auth", "jwt_deep", "business_logic",
            "lfi", "command_injection", "xxe",
            "nosql_injection", "ssti", "deserialization",
        ]

        if not success:
            return default_order

        # Sort by historical success count
        scored = [(m, success.get(m, 0)) for m in default_order]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [m for m, _ in scored]

    def generate_hypothesis(self, partial_findings: list,
                            target_info: dict) -> list:
        """
        Generate novel hypotheses based on partial findings.
        The 'insight' layer — what would a smart human think next?
        """
        hypotheses = []
        modules    = {f.get("module") for f in partial_findings}

        # Pattern-based hypothesis generation
        if "cors" in modules and "auth" not in modules:
            hypotheses.append({
                "test":     "Test CORS with authenticated endpoints",
                "reason":   "CORS found — credentials=true needed for full impact",
                "priority": 1,
            })

        if not modules:
            # Nothing found yet — suggest fresh angles
            scan_count = self.memory.get("scan_count", 0)
            if scan_count > 5:
                # We have experience — suggest what worked before
                all_success = self.memory.get("module_success", {})
                top_modules = defaultdict(int)
                for tech_key, mods in all_success.items():
                    for mod, count in mods.items():
                        top_modules[mod] += count
                top_3 = sorted(top_modules.items(),
                               key=lambda x: x[1], reverse=True)[:3]
                for mod, count in top_3:
                    hypotheses.append({
                        "test":     mod,
                        "reason":   f"Worked {count}x on similar targets",
                        "priority": 1,
                    })

        # Store novel hypothesis for feedback
        self.observe("hypothesis_generated",
                     str(len(hypotheses)), {"count": len(hypotheses)})
        return hypotheses

    def self_evaluate(self) -> dict:
        """Evaluate own performance and suggest improvements."""
        scan_count = self.memory.get("scan_count", 0)
        all_success = self.memory.get("module_success", {})
        total_finds = sum(
            sum(mods.values())
            for mods in all_success.values()
        )
        best_module = ""
        best_count  = 0
        for tech_mods in all_success.values():
            for mod, count in tech_mods.items():
                if count > best_count:
                    best_count  = count
                    best_module = mod
        return {
            "scans_completed": scan_count,
            "total_findings":  total_finds,
            "best_module":     best_module,
            "best_count":      best_count,
            "learning_rate":   total_finds / max(scan_count, 1),
        }

    def _load(self) -> dict:
        try:
            if self.memory_path.exists():
                return pickle.loads(self.memory_path.read_bytes())
        except Exception:
            pass
        return {"module_success": {}, "scan_count": 0}

    def _save(self):
        try:
            self.memory_path.parent.mkdir(parents=True, exist_ok=True)
            self.memory_path.write_bytes(pickle.dumps(self.memory))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════
# MAIN: AmonStrikeAI — All 7 Layers Unified
# ══════════════════════════════════════════════════════════════

class AmonStrikeAI:
    """
    Unified AI engine integrating all 7 layers.
    Each layer feeds the next for maximum accuracy.
    """

    def __init__(self):
        # Layer 1: Classical AI
        self.expert     = ExpertSystem()
        # Layer 2: ML
        self.anomaly    = AnomalyDetector()
        self.features   = ResponseFeatureExtractor()
        # Layer 3: Neural Network
        self.neural     = NeuralClassifier()
        # Layer 4: Deep Learning
        self.deep       = DeepLearningLayer()
        # Layer 5: Generative AI
        self.gen        = GenerativeAI()
        # Layer 6: Agentic AI
        self.agent      = AgenticLayer(self.gen, self.expert)
        # Layer 7: AGI
        self.agi        = AGILayer()

        self._load_neural()

    def analyze(self, response_data: dict, context: dict) -> dict:
        """
        Full 7-layer analysis of a security finding.
        Returns: {is_real, confidence, severity, action, report}
        """
        body    = response_data.get("body", "")
        headers = response_data.get("headers", {})
        status  = response_data.get("status_code", 0)

        # Layer 1: Expert system (fastest)
        expert_result = self.expert.evaluate(response_data, context)
        if expert_result.get("severity") == "NONE":
            self.agi.observe("false_positive", "discarded", context)
            return {"is_real": False, "confidence": expert_result["confidence"],
                    "layer": "classical_ai", "reason": expert_result["conclusion"]}

        # Layer 2: ML anomaly detection
        is_anomalous, anomaly_score = self.anomaly.is_anomalous(body, headers, status)

        # Layer 3: Neural network classification
        feature_vec  = self.features.extract(body, headers, status)
        nn_score     = self.neural.predict(feature_vec)

        # Combined confidence from layers 1-3
        combined_conf = (
            expert_result["confidence"] * 0.5 +
            (anomaly_score if is_anomalous else 1.0 - anomaly_score) * 0.25 +
            nn_score * 0.25
        )

        # Layer 6: Agent reflection
        reflection = self.agent.reflect(context, response_data)
        if reflection["verdict"] == "false_positive":
            return {"is_real": False,
                    "confidence": reflection["confidence"],
                    "layer": "agentic_ai",
                    "reason": reflection["reason"]}

        # Train neural network from this result
        label = 1.0 if combined_conf > 0.6 else 0.0
        self.neural.train(feature_vec, label)

        # Layer 7: AGI records observation
        self.agi.observe(
            "finding_analyzed",
            "confirmed" if combined_conf > 0.6 else "uncertain",
            {"severity": expert_result.get("severity", ""),
             "module": context.get("module", "")}
        )

        return {
            "is_real":    combined_conf > 0.6,
            "confidence": round(combined_conf, 3),
            "severity":   expert_result.get("severity", "MEDIUM"),
            "action":     expert_result.get("action", "report"),
            "layers_used": {
                "classical_ai": expert_result["confidence"],
                "ml":           anomaly_score,
                "neural_net":   nn_score,
            },
        }

    def plan_attack(self, tech: list, waf: str,
                    partial_findings: list) -> dict:
        """Use all AI layers to plan optimal attack strategy."""
        # Layer 7: Get optimized module order from past experience
        module_order = self.agi.get_optimized_module_order(tech)

        # Layer 7: Generate hypotheses
        hypotheses   = self.agi.generate_hypothesis(partial_findings, {"tech": tech})

        # Layer 6: Decide next action
        state        = {"findings": partial_findings, "tech": tech, "waf": waf}
        next_action  = self.agent.decide_next_action(state)

        # Layer 5: Generate targeted payloads
        payloads     = {}
        if tech and not waf:
            for vtype in ["sqli", "xss"]:
                payloads[vtype] = self.gen.generate_payloads(
                    vtype, tech, waf, str(partial_findings)[:200]
                )

        return {
            "module_order": module_order[:8],
            "next_action":  next_action,
            "hypotheses":   hypotheses[:3],
            "payloads":     payloads,
        }

    def write_report(self, finding: dict) -> str:
        """Layer 5: Generate professional H1 report."""
        return self.gen.write_h1_report(finding)

    def chain_findings(self, findings: list) -> list:
        """Layer 6: Chain findings for maximum impact."""
        return self.agent.chain_findings(findings)

    def learn(self, findings: list, target: str, tech: list):
        """Layer 7: Learn from completed scan."""
        self.agi.learn_from_session(findings, target, tech)
        self._save_neural()

    def status(self) -> dict:
        """Show AI system status."""
        perf = self.agi.self_evaluate()
        return {
            "classical_ai": f"{len(self.expert.RULES)} rules",
            "ml":           f"{self.anomaly.n_observed} observations",
            "neural_net":   f"{self.neural.trained} training samples",
            "deep_learning":"Ollama embeddings",
            "generative_ai":"Ollama deepseek-r1:14b + Claude API",
            "agentic_ai":   f"{len(self.agent.memory)} recent decisions",
            "agi":          f"{perf['scans_completed']} scans learned",
            "performance":  perf,
        }

    def _load_neural(self):
        try:
            mem = self.agi._load()
            if "neural_weights" in mem:
                self.neural.from_dict(mem["neural_weights"])
        except Exception:
            pass

    def _save_neural(self):
        try:
            mem = self.agi._load()
            mem["neural_weights"] = self.neural.to_dict()
            self.agi.memory = mem
            self.agi._save()
        except Exception:
            pass


if __name__ == "__main__":
    print("AmonStrike 7-Layer AI Engine")
    ai = AmonStrikeAI()
    print(json.dumps(ai.status(), indent=2))

    # Test each layer
    print("\n=== Layer Tests ===")

    # L1: Expert system
    result = ai.expert.evaluate(
        {"body": "uid=33(www-data) gid=33", "status_code": 200},
        {"module": "command_injection"}
    )
    print(f"L1 Classical AI: {result['conclusion']} ({result['confidence']})")

    # L2: ML anomaly
    is_anom, score = ai.anomaly.is_anomalous(
        "SQL syntax error near ''", {}, 500
    )
    print(f"L2 ML Anomaly:   score={score:.3f} anomalous={is_anom}")

    # L3: Neural net
    features = ai.features.extract("error sql syntax", {}, 500)
    prob = ai.neural.predict(features)
    print(f"L3 Neural Net:   vulnerability_prob={prob:.3f}")

    # L6: Agent decision
    decision = ai.agent.decide_next_action({"findings":[], "tech":["php","mysql"]})
    print(f"L6 Agentic AI:   {decision['action']} ({decision['reason']})")

    # L7: AGI status
    perf = ai.agi.self_evaluate()
    print(f"L7 AGI:          {perf['scans_completed']} scans, "
          f"best={perf['best_module']}")
