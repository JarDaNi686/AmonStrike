#!/usr/bin/env python3
"""
AmonStrike — Mathematical Diff Engine
Z-score anomaly detection across HTTP responses for zero-day discovery.
"""
import math, hashlib
from collections import defaultdict


class DiffEngine:
    def __init__(self, z_threshold: float = 3.0):
        self.z_thresh = z_threshold
        self.baseline: dict[str, list] = defaultdict(list)

    def record(self, endpoint: str, response):
        """Add a response sample to the baseline pool."""
        self.baseline[endpoint].append(self._features(response))

    def _features(self, r) -> dict:
        body = r.text if hasattr(r, "text") else str(r)
        return {
            "length":     len(body),
            "status":     getattr(r, "status_code", 200),
            "word_count": len(body.split()),
            "hash":       hashlib.md5(body.encode()).hexdigest(),
            "reflections": body.count("AMON_REFLECT"),
        }

    def _stats(self, values: list) -> tuple:
        n = len(values)
        if n < 2:
            return 0.0, 1.0
        mu  = sum(values) / n
        var = sum((v - mu) ** 2 for v in values) / n
        return mu, math.sqrt(var) or 1.0

    def is_anomaly(self, endpoint: str, response) -> dict:
        """
        Compare response to baseline. Returns anomaly dict if Z > threshold.
        Z-score: z = (x - μ) / σ
        """
        feats   = self._features(response)
        samples = self.baseline.get(endpoint, [])
        if len(samples) < 3:
            return {}

        anomalies = {}
        for key in ("length", "word_count"):
            vals = [s[key] for s in samples]
            mu, sigma = self._stats(vals)
            z = abs(feats[key] - mu) / sigma
            if z > self.z_thresh:
                anomalies[key] = {"z": round(z, 2), "value": feats[key],
                                  "baseline_mean": round(mu, 1)}

        # Unique hash = never-seen response structure
        known_hashes = {s["hash"] for s in samples}
        if feats["hash"] not in known_hashes and len(samples) >= 5:
            anomalies["unique_structure"] = {"hash": feats["hash"]}

        if anomalies:
            return {
                "endpoint":  endpoint,
                "status":    feats["status"],
                "anomalies": anomalies,
                "severity":  "HIGH" if len(anomalies) >= 2 else "MEDIUM",
                "zero_day_candidate": len(anomalies) >= 2,
            }
        return {}

    def diff_pair(self, r1, r2) -> dict:
        """Direct diff between two responses (auth vs unauth, param A vs B)."""
        f1, f2 = self._features(r1), self._features(r2)
        diffs   = {}
        for key in ("length", "status", "word_count"):
            if f1[key] != f2[key]:
                diffs[key] = {"before": f1[key], "after": f2[key]}
        if f1["hash"] != f2["hash"]:
            diffs["content_changed"] = True
        return diffs
