"""Risk Engine: blend heuristic + ML + threat intel into final risk_score.

Final risk_score is NOT a probability that the site is phishing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import get_settings
from app.risk.rules import Finding, RuleResult, evaluate_rules
from app.scanners.blacklist_checker import ThreatIntelResult


@dataclass
class RiskResult:
    risk_score: int
    risk_level: str
    rule_score: int
    ml_phishing_probability: float | None
    threat_intel: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    breakdown: dict[str, Any] = field(default_factory=dict)
    disclaimer: str = (
        "Điểm rủi ro phản ánh các dấu hiệu đáng ngờ, "
        "không phải phán quyết pháp lý rằng website chắc chắn lừa đảo."
    )

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "rule_score": self.rule_score,
            "ml_phishing_probability": self.ml_phishing_probability,
            "threat_intel": self.threat_intel,
            "findings": [f.to_dict() for f in self.findings],
            "breakdown": self.breakdown,
            "disclaimer": self.disclaimer,
        }


def risk_level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


class RiskEngine:
    def evaluate(
        self,
        features: dict[str, Any],
        *,
        ml_phishing_probability: float | None,
        threat_intel: ThreatIntelResult,
        meta: dict[str, Any] | None = None,
    ) -> RiskResult:
        settings = get_settings()
        rule_result: RuleResult = evaluate_rules(features, meta=meta)
        findings = list(rule_result.findings)

        ti_dict = threat_intel.to_dict()
        if threat_intel.hit:
            findings.append(
                Finding(
                    type="blacklist_hit",
                    severity="high",
                    description=(
                        f"URL/tên miền nằm trong danh sách đen "
                        f"(nguồn: {threat_intel.source}, khớp: {threat_intel.matched_value})."
                    ),
                    source="threat_intel",
                    points=settings.threat_intel_floor,
                )
            )

        # Blend with overlap awareness:
        # When ML and rules both fire on young domains / brand, slightly damp ML contribution.
        rule_score = rule_result.rule_score
        ml_prob = ml_phishing_probability

        if threat_intel.hit:
            blended = max(settings.threat_intel_floor, rule_score)
            if ml_prob is not None:
                blended = max(blended, int(round(0.5 * blended + 0.5 * (ml_prob * 100))))
            method = "threat_intel_floor"
        elif ml_prob is None:
            blended = rule_score
            method = "rule_only"
        else:
            # Cap double-counting: if rule already high from overlapping signals,
            # reduce ML weight slightly.
            w_rule = settings.weight_rule
            w_ml = settings.weight_ml
            if rule_score >= 50 and ml_prob >= 0.5:
                w_ml *= 0.85
                w_rule = 1.0 - w_ml
            blended = int(round(w_rule * rule_score + w_ml * (ml_prob * 100)))
            method = "weighted_blend"

        blended = max(0, min(100, blended))
        level = risk_level_from_score(blended)

        breakdown = {
            "method": method,
            "rule_score": rule_score,
            "ml_phishing_probability": ml_prob,
            "threat_intel_hit": threat_intel.hit,
            "weight_rule": settings.weight_rule,
            "weight_ml": settings.weight_ml,
            "note": "Điểm rủi ro cuối cùng là chỉ số tổng hợp, không phải P(lừa đảo).",
        }

        return RiskResult(
            risk_score=blended,
            risk_level=level,
            rule_score=rule_score,
            ml_phishing_probability=ml_prob,
            threat_intel=ti_dict,
            findings=findings,
            breakdown=breakdown,
        )
