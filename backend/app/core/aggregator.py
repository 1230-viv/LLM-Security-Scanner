from __future__ import annotations

from collections import defaultdict

from app.schemas.attack import Vulnerability

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


class DetectionAggregator:
    """Merges, normalizes, and prioritizes vulnerabilities."""

    def aggregate_vulnerabilities(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        if not vulnerabilities:
            return []

        grouped: dict[tuple[str, str], list[Vulnerability]] = defaultdict(list)
        for vulnerability in vulnerabilities:
            grouped[(vulnerability.type, vulnerability.attack_prompt)].append(vulnerability)

        merged: list[Vulnerability] = []
        for items in grouped.values():
            severity = max(items, key=lambda item: SEVERITY_WEIGHT.get(item.severity, 0)).severity
            confidence = sum(item.confidence for item in items) / len(items)
            evidence: dict[str, object] = {}
            for item in items:
                evidence.update(item.evidence)

            merged.append(
                Vulnerability(
                    type=items[0].type,
                    severity=severity,
                    attack_prompt=items[0].attack_prompt,
                    response_text=items[0].response_text,
                    detection_method=",".join(sorted({item.detection_method for item in items})),
                    confidence=round(confidence, 4),
                    evidence=evidence,
                    suggested_fix=items[0].suggested_fix,
                )
            )

        return sorted(
            merged,
            key=lambda item: (SEVERITY_WEIGHT.get(item.severity, 0), item.confidence),
            reverse=True,
        )
