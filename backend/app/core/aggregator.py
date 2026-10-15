from __future__ import annotations

from collections import defaultdict

from app.schemas.attack import Vulnerability

VERDICT_WEIGHT = {
    "CONFIRMED": 4,
    "SUSPECTED": 3,
    "INCONCLUSIVE": 2,
    "NOT_REPRODUCED": 1,
}
SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


class DetectionAggregator:
    """Merge, normalize, and prioritize findings from the same test event."""

    def aggregate_vulnerabilities(
        self,
        vulnerabilities: list[Vulnerability],
    ) -> list[Vulnerability]:
        if not vulnerabilities:
            return []

        # Stable test IDs prevent distinct cases with identical prompts from colliding.
        grouped: dict[tuple[str, str], list[Vulnerability]] = defaultdict(list)
        for vulnerability in vulnerabilities:
            test_case_id = str(
                vulnerability.evidence.get("test_case_id", vulnerability.attack_prompt)
            )
            grouped[(test_case_id, vulnerability.attack_prompt)].append(vulnerability)

        merged: list[Vulnerability] = []
        for items in grouped.values():
            # Select top item based on verdict priority, then severity, then confidence
            top_item = max(
                items,
                key=lambda item: (
                    VERDICT_WEIGHT.get(getattr(item, "verdict", "SUSPECTED"), 0),
                    SEVERITY_WEIGHT.get(item.severity, 0),
                    item.confidence,
                ),
            )
            severity = max(items, key=lambda item: SEVERITY_WEIGHT.get(item.severity, 0)).severity
            verdict = max(
                items,
                key=lambda item: VERDICT_WEIGHT.get(getattr(item, "verdict", "SUSPECTED"), 0),
            ).verdict

            if len({item.type for item in items}) == 1:
                confidence = sum(item.confidence for item in items) / len(items)
            else:
                confidence = max(item.confidence for item in items)

            evidence: dict[str, object] = {}
            detector_evidence: list[dict[str, object]] = []
            for item in items:
                detector_evidence.append(
                    {
                        "detector": item.detection_method,
                        "type": item.type,
                        "verdict": item.verdict,
                        "evidence": item.evidence,
                    }
                )
                for key, value in item.evidence.items():
                    if key not in evidence:
                        evidence[key] = value
                    elif evidence[key] != value:
                        conflict_key = f"conflicting_{key}"
                        prior = evidence.get(conflict_key, [])
                        if not isinstance(prior, list):
                            prior = [prior]
                        if value not in prior:
                            prior.append(value)
                        evidence[conflict_key] = prior

            evidence["verdict"] = verdict
            evidence["all_types"] = sorted(list({item.type for item in items}))
            evidence["detector_evidence"] = detector_evidence

            merged.append(
                Vulnerability(
                    type=top_item.type,
                    severity=severity,
                    verdict=verdict,
                    attack_prompt=items[0].attack_prompt,
                    response_text=items[0].response_text,
                    detection_method=",".join(sorted({item.detection_method for item in items})),
                    confidence=round(confidence, 4),
                    evidence=evidence,
                    suggested_fix=top_item.suggested_fix,
                )
            )

        return sorted(
            merged,
            key=lambda item: (
                VERDICT_WEIGHT.get(item.verdict, 0),
                SEVERITY_WEIGHT.get(item.severity, 0),
                item.confidence,
            ),
            reverse=True,
        )
