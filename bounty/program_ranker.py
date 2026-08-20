"""
AmonStrike — Program Ranker
Ranks bug bounty programs by profit potential for a researcher.

Scoring factors:
  - Bounty amount (max payout)
  - Response time (faster = better)
  - Competition level (estimated)
  - Program age (newer = less competition)
  - Scope size (more targets = more opportunities)
  - Automation allowed
  - VDP vs paid
  - Platform reputation

Output: Ranked list with score 0-100 and recommended approach.
"""

import sys
import math
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.dirname(__file__)))


class ProgramRanker:
    """
    Ranks bug bounty programs by profit potential.
    Considers bounty amount, response time, competition, scope.
    """

    # Weight factors for scoring (must sum to 100)
    WEIGHTS = {
        "bounty_potential":   30,   # How much money can be made
        "response_time":      15,   # How fast they respond
        "automation_allowed": 20,   # Can we use AmonStrike fully
        "scope_size":         15,   # How many targets to test
        "competition":        10,   # Estimated competition level
        "platform_trust":     10,   # Platform reliability
    }

    # Platform trust scores
    PLATFORM_TRUST = {
        "hackerone": 95,
        "bugcrowd":  90,
        "intigriti": 85,
        "yeswehack": 80,
        "direct":    70,
        "immunefi":  85,
    }

    # Researcher profile (can be customized)
    DEFAULT_PROFILE = {
        "skill_level":    "intermediate",   # beginner/intermediate/expert
        "prefer_paid":    True,             # Paid vs VDP
        "min_bounty":     100,              # Minimum bounty to consider
        "time_available": "weekend",        # weekend/parttime/fulltime
        "focus_vulns":    ["sqli","xss","ssrf","idor","rce"],
    }

    def __init__(self, researcher_profile=None):
        self.profile = researcher_profile or self.DEFAULT_PROFILE

    def rank_programs(self, programs: list) -> list:
        """
        Rank a list of programs.
        Returns sorted list with rank_score and recommendations added.
        """
        ranked = []
        for prog in programs:
            score = self._calculate_score(prog)
            prog  = dict(prog)
            prog["rank_score"]      = score
            prog["rank_tier"]       = self._tier(score)
            prog["recommendation"]  = self._recommend(prog, score)
            prog["estimated_earning"] = self._estimate_earning(prog)
            ranked.append(prog)

        ranked.sort(key=lambda p: p["rank_score"], reverse=True)
        return ranked

    def _calculate_score(self, prog: dict) -> float:
        """Calculate 0-100 rank score for a program."""
        scores = {}

        # 1. Bounty potential (0-30)
        max_bounty = prog.get("bounty_max", 0) or 0
        if prog.get("vdp_only"):
            scores["bounty_potential"] = 5   # VDP = minimal score
        elif max_bounty >= 50000:
            scores["bounty_potential"] = 30
        elif max_bounty >= 10000:
            scores["bounty_potential"] = 25
        elif max_bounty >= 5000:
            scores["bounty_potential"] = 20
        elif max_bounty >= 1000:
            scores["bounty_potential"] = 15
        elif max_bounty >= 500:
            scores["bounty_potential"] = 10
        elif max_bounty > 0:
            scores["bounty_potential"] = 5
        else:
            scores["bounty_potential"] = 0

        # 2. Response time (0-15) — faster is better
        resp_days = prog.get("response_time", 30) or 30
        if resp_days <= 1:
            scores["response_time"] = 15
        elif resp_days <= 3:
            scores["response_time"] = 12
        elif resp_days <= 7:
            scores["response_time"] = 9
        elif resp_days <= 14:
            scores["response_time"] = 6
        elif resp_days <= 30:
            scores["response_time"] = 3
        else:
            scores["response_time"] = 0

        # 3. Automation allowed (0-20)
        if prog.get("allows_auto"):
            scores["automation_allowed"] = 20
        else:
            scores["automation_allowed"] = 5   # Manual only

        # 4. Scope size (0-15) — estimated from domain count
        raw = prog.get("raw_json","") or ""
        domain_count = raw.count("*.") + raw.count(".com") + raw.count(".io")
        if domain_count >= 20:
            scores["scope_size"] = 15
        elif domain_count >= 10:
            scores["scope_size"] = 12
        elif domain_count >= 5:
            scores["scope_size"] = 9
        elif domain_count >= 2:
            scores["scope_size"] = 6
        else:
            scores["scope_size"] = 3

        # 5. Competition level (0-10) — estimated by platform + bounty
        # High bounty = high competition
        if max_bounty >= 50000:
            scores["competition"] = 2    # Very competitive
        elif max_bounty >= 10000:
            scores["competition"] = 4
        elif max_bounty >= 1000:
            scores["competition"] = 7
        else:
            scores["competition"] = 10  # Low bounty = less competition

        # 6. Platform trust (0-10)
        platform = prog.get("platform","direct")
        trust    = self.PLATFORM_TRUST.get(platform, 60)
        scores["platform_trust"] = int(trust / 10)

        # Calculate weighted total
        total = sum(
            scores.get(k, 0) * (self.WEIGHTS[k] / max(self.WEIGHTS[k], 1))
            for k in self.WEIGHTS
        )

        # Apply researcher profile modifiers
        if self.profile.get("prefer_paid") and prog.get("vdp_only"):
            total *= 0.3

        if self.profile.get("min_bounty", 0) > max_bounty and not prog.get("vdp_only"):
            total *= 0.5

        return round(min(100, max(0, total)), 1)

    def _tier(self, score: float) -> str:
        """Map score to tier label."""
        if score >= 80: return "S-Tier"
        if score >= 65: return "A-Tier"
        if score >= 50: return "B-Tier"
        if score >= 35: return "C-Tier"
        return "D-Tier"

    def _recommend(self, prog: dict, score: float) -> str:
        """Generate actionable recommendation."""
        name    = prog.get("name","")
        vdp     = prog.get("vdp_only",False)
        auto    = prog.get("allows_auto",False)
        max_b   = prog.get("bounty_max",0) or 0

        if score >= 80:
            return f"🔥 HIGH PRIORITY — Run full AmonStrike deep scan immediately"
        elif score >= 65:
            if auto:
                return f"⚡ Run AmonStrike normal scan — good bounty/effort ratio"
            else:
                return f"Manual testing recommended — automation restricted"
        elif score >= 50:
            if vdp:
                return f"📋 VDP — Good for CVE experience and reputation building"
            return f"Medium priority — scan on weekends for passive income"
        elif score >= 35:
            return f"Low priority — consider only if no higher-ranked programs available"
        else:
            return f"Skip — poor bounty/effort ratio for your profile"

    def _estimate_earning(self, prog: dict) -> dict:
        """Estimate realistic earnings from this program."""
        max_b    = prog.get("bounty_max", 0) or 0
        min_b    = prog.get("bounty_min", 0) or 0
        vdp      = prog.get("vdp_only", False)
        auto     = prog.get("allows_auto", False)

        if vdp or max_b == 0:
            return {
                "low":    0,
                "medium": 0,
                "high":   0,
                "currency": "USD",
                "note":   "VDP — reputation/CVE value only",
            }

        # Realistic finding rates based on scope and experience
        avg_b  = (max_b + min_b) / 2
        low    = int(min_b * 0.8)
        medium = int(avg_b * 0.6)
        high   = int(max_b * 0.4)

        note = (
            "Per valid finding. Rates vary significantly by researcher skill."
            if not auto else
            "Automated scan may find multiple issues. Estimate per unique finding."
        )

        return {
            "low":      low,
            "medium":   medium,
            "high":     high,
            "currency": prog.get("currency","USD"),
            "note":     note,
        }

    def get_top_n(self, programs: list, n: int = 10,
                  exclude_vdp: bool = True) -> list:
        """Get top N programs after ranking."""
        ranked = self.rank_programs(programs)
        if exclude_vdp:
            ranked = [p for p in ranked if not p.get("vdp_only")]
        return ranked[:n]

    def get_practice_targets(self, programs: list) -> list:
        """Get safe practice targets for tool testing."""
        return [
            p for p in programs
            if p.get("id","").startswith("direct_vulnweb") or
               p.get("id","").startswith("direct_hackyou") or
               "vulnweb" in p.get("url","") or
               "hackthebox" in p.get("url","")
        ]

    def print_leaderboard(self, programs: list, limit: int = 10):
        """Print ranked leaderboard to terminal."""
        ranked = self.rank_programs(programs)[:limit]

        print(f"\n{'─'*80}")
        print(f"{'⚡ AMONSTRIKE PROGRAM LEADERBOARD':^80}")
        print(f"{'─'*80}")
        print(f"{'#':<3} {'Score':<7} {'Tier':<8} {'Name':<30} {'Max $':<10} {'Auto':<5}")
        print(f"{'─'*80}")

        tier_colors = {
            "S-Tier": "\033[91m",
            "A-Tier": "\033[93m",
            "B-Tier": "\033[92m",
            "C-Tier": "\033[96m",
            "D-Tier": "\033[90m",
        }

        for i, p in enumerate(ranked, 1):
            tier  = p.get("rank_tier","")
            tc    = tier_colors.get(tier,"\033[0m")
            score = p.get("rank_score",0)
            name  = p.get("name","")[:28]
            max_b = p.get("bounty_max",0) or 0
            auto  = "✓" if p.get("allows_auto") else "✗"
            b_str = f"${max_b:,}" if max_b > 0 else "VDP"

            print(f"{i:<3} {score:<7.1f} {tc}{tier:<8}\033[0m {name:<30} {b_str:<10} {auto}")

        print(f"{'─'*80}\n")


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== PROGRAM RANKER REGRESSION TESTS ===")
    passed = failed = 0

    ranker = ProgramRanker()

    sample_programs = [
        {"id":"p1","name":"BigCo","platform":"hackerone","bounty_min":500,
         "bounty_max":50000,"vdp_only":False,"allows_auto":True,
         "response_time":2,"raw_json":"*.bigco.com *.api.bigco.com","currency":"USD"},
        {"id":"p2","name":"SmallCo","platform":"bugcrowd","bounty_min":100,
         "bounty_max":1000,"vdp_only":False,"allows_auto":True,
         "response_time":7,"raw_json":"app.smallco.com","currency":"USD"},
        {"id":"p3","name":"GovAgency","platform":"direct","bounty_min":0,
         "bounty_max":0,"vdp_only":True,"allows_auto":False,
         "response_time":30,"raw_json":"*.gov","currency":"USD"},
        {"id":"p4","name":"StartupXYZ","platform":"intigriti","bounty_min":200,
         "bounty_max":5000,"vdp_only":False,"allows_auto":True,
         "response_time":3,"raw_json":"*.startupxyz.io *.api.startupxyz.io","currency":"EUR"},
    ]

    tests = [
        ("rank_programs returns list",
         lambda: isinstance(ranker.rank_programs(sample_programs), list)),

        ("All programs ranked",
         lambda: len(ranker.rank_programs(sample_programs)) == 4),

        ("Scores are 0-100",
         lambda: all(
             0 <= p["rank_score"] <= 100
             for p in ranker.rank_programs(sample_programs)
         )),

        ("Higher bounty ranks higher",
         lambda: (
             ranked := ranker.rank_programs(sample_programs),
             ranked[0]["bounty_max"] >= ranked[-1]["bounty_max"]
         )[1]),

        ("VDP scores lower than paid",
         lambda: (
             ranked := ranker.rank_programs(sample_programs),
             next(p for p in ranked if p["id"]=="p3")["rank_score"] <
             next(p for p in ranked if p["id"]=="p1")["rank_score"]
         )[1]),

        ("Tier assigned to all",
         lambda: all(
             p.get("rank_tier") in ["S-Tier","A-Tier","B-Tier","C-Tier","D-Tier"]
             for p in ranker.rank_programs(sample_programs)
         )),

        ("Recommendation generated",
         lambda: all(
             len(p.get("recommendation","")) > 0
             for p in ranker.rank_programs(sample_programs)
         )),

        ("Earning estimate for paid program",
         lambda: (
             ranked := ranker.rank_programs(sample_programs),
             next(p for p in ranked if p["id"]=="p1")["estimated_earning"]["high"] > 0
         )[1]),

        ("Earning estimate = 0 for VDP",
         lambda: (
             ranked := ranker.rank_programs(sample_programs),
             next(p for p in ranked if p["id"]=="p3")["estimated_earning"]["high"] == 0
         )[1]),

        ("get_top_n returns N programs",
         lambda: len(ranker.get_top_n(sample_programs, n=2)) == 2),

        ("get_top_n excludes VDP when asked",
         lambda: all(
             not p.get("vdp_only")
             for p in ranker.get_top_n(sample_programs, exclude_vdp=True)
         )),

        ("Practice targets identified",
         lambda: isinstance(ranker.get_practice_targets(sample_programs), list)),

        ("Weights sum to 100",
         lambda: sum(ranker.WEIGHTS.values()) == 100),

        ("Score is deterministic",
         lambda: (
             ranker._calculate_score(sample_programs[0]) ==
             ranker._calculate_score(sample_programs[0])
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
    import sys
    rp, rf = run_regression_tests()
    print(f"\nTOTAL: {rp} passed  {rf} failed")
    sys.exit(0 if rf==0 else 1)
