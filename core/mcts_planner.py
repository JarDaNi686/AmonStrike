#!/usr/bin/env python3
"""
AmonStrike — MCTS Attack Path Planner
Monte Carlo Tree Search for optimal exploit chain selection.
UCB1 = X̄ + C√(ln N / n)
"""
import math, random, time
from dataclasses import dataclass, field
from typing import Optional


ATTACK_ACTIONS = [
    "recon_endpoints", "recon_params", "recon_js",
    "test_auth_bypass", "test_idor", "test_sqli",
    "test_xss", "test_ssrf", "test_xxe", "test_ssti",
    "test_rce", "test_path_traversal", "test_open_redirect",
    "test_rate_limit", "test_csrf", "github_osint",
    "chain_idor_ato", "chain_ssrf_rce", "chain_xss_admin",
]

C = 1.414  # UCB1 exploration constant


@dataclass
class Node:
    action:   str
    parent:   Optional["Node"] = field(default=None, repr=False)
    children: list             = field(default_factory=list, repr=False)
    visits:   int              = 0
    reward:   float            = 0.0
    depth:    int              = 0

    def ucb1(self) -> float:
        if self.visits == 0:
            return float("inf")
        N = self.parent.visits if self.parent else self.visits
        return (self.reward / self.visits) + C * math.sqrt(math.log(N) / self.visits)

    def is_leaf(self) -> bool:
        return not self.children

    def best_child(self) -> "Node":
        return max(self.children, key=lambda c: c.ucb1())

    def expand(self, available: list):
        used = {c.action for c in self.children}
        for act in available:
            if act not in used:
                self.children.append(Node(act, parent=self, depth=self.depth + 1))

    def rollout_value(self) -> float:
        """Heuristic rollout: simulate random path, return expected reward."""
        score = 0.0
        # Higher-value actions score more
        priority = {
            "chain_idor_ato": 1.0, "chain_ssrf_rce": 1.0, "chain_xss_admin": 0.9,
            "test_rce": 0.95, "test_sqli": 0.85, "test_ssrf": 0.8,
            "test_idor": 0.75, "test_auth_bypass": 0.7,
            "recon_js": 0.6, "github_osint": 0.65,
        }
        score = priority.get(self.action, 0.3)
        # Chain actions get bonus
        if self.parent and "chain" in self.action:
            parent_act = self.parent.action
            if "idor" in parent_act and "idor_ato" in self.action:
                score += 0.2
        return min(score + random.uniform(-0.1, 0.1), 1.0)

    def backprop(self, value: float):
        self.visits += 1
        self.reward += value
        if self.parent:
            self.parent.backprop(value)


class MCTSPlanner:
    def __init__(self, time_limit: float = 2.0, max_depth: int = 5):
        self.time_limit = time_limit
        self.max_depth  = max_depth

    def plan(self, context: dict) -> list:
        """
        Run MCTS from context (findings so far, target type).
        Returns ordered list of recommended attack actions.
        """
        available = self._filter_actions(context)
        root      = Node("root")
        root.expand(available)

        deadline = time.time() + self.time_limit
        while time.time() < deadline:
            leaf = self._select(root)
            if leaf.depth < self.max_depth and leaf.visits > 0:
                leaf.expand(available)
                if leaf.children:
                    leaf = random.choice(leaf.children)
            value = leaf.rollout_value()
            leaf.backprop(value)

        # Return top actions sorted by visit-weighted reward
        return [
            c.action
            for c in sorted(root.children,
                             key=lambda c: (c.reward / c.visits) if c.visits else 0,
                             reverse=True)
        ]

    def _select(self, node: Node) -> Node:
        while not node.is_leaf():
            node = node.best_child()
        return node

    def _filter_actions(self, ctx: dict) -> list:
        acts = list(ATTACK_ACTIONS)
        findings = ctx.get("findings", [])
        ftypes   = {f.get("type","") for f in findings}

        # Unlock chain attacks only if prerequisite found
        if "idor" not in str(ftypes):
            acts = [a for a in acts if a != "chain_idor_ato"]
        if "ssrf" not in str(ftypes):
            acts = [a for a in acts if a != "chain_ssrf_rce"]
        if "xss" not in str(ftypes):
            acts = [a for a in acts if a != "chain_xss_admin"]

        # Deprioritize already-done actions
        done = set(ctx.get("completed_actions", []))
        return [a for a in acts if a not in done] or list(ATTACK_ACTIONS)
