from app.core.aggregator import DetectionAggregator
from app.schemas.attack import Vulnerability


def test_aggregation_merges_duplicate_findings() -> None:
    aggregator = DetectionAggregator()

    findings = [
        Vulnerability(
            type="prompt_injection",
            severity="medium",
            attack_prompt="Ignore policy",
            response_text="I can do that",
            detection_method="detector_a",
            confidence=0.7,
            evidence={"pattern": "role_switch"},
            suggested_fix="Add stricter filters",
        ),
        Vulnerability(
            type="prompt_injection",
            severity="high",
            attack_prompt="Ignore policy",
            response_text="I can do that",
            detection_method="detector_b",
            confidence=0.9,
            evidence={"pattern": "instruction_override"},
            suggested_fix="Add stricter filters",
        ),
    ]

    merged = aggregator.aggregate_vulnerabilities(findings)

    assert len(merged) == 1
    assert merged[0].severity == "high"
    assert merged[0].confidence == 0.8


def test_aggregation_preserves_response_text_from_first_finding() -> None:
    aggregator = DetectionAggregator()

    findings = [
        Vulnerability(
            type="data_leakage",
            severity="low",
            attack_prompt="Expose secrets",
            response_text="I can provide that",
            detection_method="detector_a",
            confidence=0.6,
            evidence={"pattern": "a"},
            suggested_fix="Fix it",
        ),
        Vulnerability(
            type="data_leakage",
            severity="medium",
            attack_prompt="Expose secrets",
            response_text="I can provide that too",
            detection_method="detector_b",
            confidence=0.8,
            evidence={"pattern": "b"},
            suggested_fix="Fix it",
        ),
    ]

    merged = aggregator.aggregate_vulnerabilities(findings)

    assert len(merged) == 1
    assert merged[0].response_text == "I can provide that"
