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


def test_aggregation_preserves_detector_level_evidence_and_conflicts() -> None:
    aggregator = DetectionAggregator()
    findings = [
        Vulnerability(
            type="prompt_injection",
            severity="medium",
            attack_prompt="Override policy",
            response_text="mode enabled",
            detection_method="prompt_injection_detector",
            confidence=0.7,
            verdict="SUSPECTED",
            evidence={"signal": "role_claim", "verdict": "SUSPECTED"},
            suggested_fix="Review",
        ),
        Vulnerability(
            type="jailbreak",
            severity="high",
            attack_prompt="Override policy",
            response_text="unsafe payload",
            detection_method="jailbreak_detector",
            confidence=0.9,
            verdict="CONFIRMED",
            evidence={"signal": "behavioral_violation", "verdict": "CONFIRMED"},
            suggested_fix="Review",
        ),
    ]

    merged = aggregator.aggregate_vulnerabilities(findings)[0]

    assert len(merged.evidence["detector_evidence"]) == 2
    assert merged.evidence["conflicting_verdict"] == ["CONFIRMED"]
    assert {item["detector"] for item in merged.evidence["detector_evidence"]} == {
        "prompt_injection_detector",
        "jailbreak_detector",
    }


def test_aggregation_does_not_merge_distinct_test_case_ids_with_same_prompt() -> None:
    findings = [
        Vulnerability(
            type="jailbreak",
            severity="medium",
            attack_prompt="same prompt",
            response_text="first",
            detection_method="jailbreak_detector",
            confidence=0.7,
            evidence={"test_case_id": "case-a"},
            suggested_fix="Review",
        ),
        Vulnerability(
            type="jailbreak",
            severity="medium",
            attack_prompt="same prompt",
            response_text="second",
            detection_method="jailbreak_detector",
            confidence=0.7,
            evidence={"test_case_id": "case-b"},
            suggested_fix="Review",
        ),
    ]

    merged = DetectionAggregator().aggregate_vulnerabilities(findings)

    assert len(merged) == 2
    assert {item.evidence["test_case_id"] for item in merged} == {"case-a", "case-b"}
