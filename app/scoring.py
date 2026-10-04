"""FINDINGS -> SCORE. Methodology documented in docs/SCORING.md.

1. Each category has a weight (sum = 100).
2. Each failed rule removes ``weight * PENALTY[severity]`` from its category,
   never below zero. INFO findings and "unknown" results remove nothing.
3. Categories with no applicable rule (e.g. no cookies set) are excluded and the
   remaining weights are rescaled to 100, so a site is not punished or rewarded
   for features it does not have.
4. Caps keep the number honest: any CRITICAL caps the score at 40, any HIGH at 70.
5. Grade: A >= 90, B >= 75, C >= 60, D >= 40, else F.

Every point lost is attributed to a specific finding (``deductions``).
"""
from __future__ import annotations

from collections import Counter

from .rules.engine import Result

WEIGHTS = {"email": 30, "tls": 25, "headers": 15, "cookies": 10, "dns": 10, "exposure": 10}
PENALTY = {"critical": 1.0, "high": 0.5, "medium": 0.25, "low": 0.1, "info": 0.0}
CAPS = (("critical", 40), ("high", 70))
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def grade_for(score: int) -> str:
    for g, threshold in (("A", 90), ("B", 75), ("C", 60), ("D", 40)):
        if score >= threshold:
            return g
    return "F"


def compute_score(results: list[Result]) -> dict:
    applicable = {c for c in WEIGHTS if any(r.category == c and r.status in ("pass", "fail") for r in results)}
    total_weight = sum(WEIGHTS[c] for c in applicable) or 1
    scale = 100 / total_weight
    categories, deductions = {}, []
    for cat in WEIGHTS:
        if cat not in applicable:
            categories[cat] = {"weight": 0, "earned": 0, "applicable": False}
            continue
        remaining = float(WEIGHTS[cat])
        for r in sorted((r for r in results if r.category == cat and r.status == "fail"),
                        key=lambda r: SEVERITY_ORDER.index(r.severity)):
            loss = min(remaining, WEIGHTS[cat] * PENALTY[r.severity])
            if loss > 0:
                deductions.append({"rule_id": r.rule_id, "severity": r.severity, "points": round(loss * scale, 1)})
                remaining -= loss
        categories[cat] = {"weight": round(WEIGHTS[cat] * scale, 1), "earned": round(remaining * scale, 1),
                           "applicable": True}
    raw = round(sum(c["earned"] for c in categories.values()))
    fails = [r for r in results if r.status == "fail"]
    counts = Counter(r.severity for r in fails)
    cap_reason = None
    score = raw
    for sev, cap in CAPS:
        if counts.get(sev) and score > cap:
            score, cap_reason = cap, sev
            break
    return {
        "score": score,
        "raw_score": raw,
        "grade": grade_for(score),
        "cap": cap_reason,
        "counts": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "passed": sum(1 for r in results if r.status == "pass"),
        "unknown": sum(1 for r in results if r.status == "unknown"),
        "categories": categories,
        "deductions": deductions,
    }
