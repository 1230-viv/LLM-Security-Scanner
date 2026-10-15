from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from datetime import UTC, datetime

from evaluation_dataset import EVALUATION_CASES

from app.core.aggregator import DetectionAggregator
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.response_integrity import ResponseIntegrityDetector
from app.schemas.attack import AttackExecutionResult


def _result(case) -> AttackExecutionResult:
    messages = [
        {"role": "system", "content": value}
        for value in case.protected_context.values()
    ]
    messages.append({"role": "user", "content": case.prompt})
    payload = case.response_payload or {"message": {"content": case.response}}
    return AttackExecutionResult(
        prompt_id=case.case_id,
        test_case_id=case.case_id,
        prompt_text=case.prompt,
        request_payload={"messages": messages},
        response_payload=payload,
        status_code=200,
        timestamp=datetime.now(UTC),
        active_canaries=case.active_canaries,
    )


def _metrics(rows: list[tuple[bool, bool]]) -> dict[str, float | int]:
    tp = sum(pred and expected for pred, expected in rows)
    fp = sum(pred and not expected for pred, expected in rows)
    tn = sum(not pred and not expected for pred, expected in rows)
    fn = sum(not pred and expected for pred, expected in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fnr": fn / (fn + tp) if fn + tp else 0.0,
    }


def _verdict_metrics(
    findings: list,
    expected_vulnerable: bool,
) -> tuple[bool, bool]:
    """Return (confirmed security result, expected security result).

    A finding with SUSPECTED or INCONCLUSIVE verdict is not a confirmed
    vulnerability. Response-integrity defects are findings, but not security
    vulnerability confirmations.
    """
    confirmed = any(finding.verdict == "CONFIRMED" for finding in findings)
    return confirmed, expected_vulnerable


def _case_record(case, findings: list) -> dict[str, object]:
    actual_finding = bool(findings)
    actual_verdict = findings[0].verdict if findings else "NOT_REPRODUCED"
    return {
        "test_case_id": case.case_id,
        "category": case.category,
        "expected_finding": case.expected_finding,
        "expected_verdict": case.expected_verdict,
        "expected_vulnerable": case.expected_vulnerable,
        "actual_finding": actual_finding,
        "actual_verdict": actual_verdict,
        "verdict_match": actual_verdict == case.expected_verdict,
        "findings": findings,
    }


def _records_metrics(records: list[dict[str, object]]) -> dict[str, float | int]:
    return _metrics(
        [
            (bool(record["actual_finding"]), bool(record["expected_finding"]))
            for record in records
        ]
    )


def test_verdict_metrics_keep_suspected_and_inconclusive_out_of_confirmed() -> None:
    class Finding:
        def __init__(self, verdict: str) -> None:
            self.verdict = verdict

    assert _verdict_metrics([Finding("CONFIRMED")], True) == (True, True)
    assert _verdict_metrics([Finding("SUSPECTED")], False) == (False, False)
    assert _verdict_metrics([Finding("INCONCLUSIVE")], False) == (False, False)
    assert _verdict_metrics([Finding("NOT_REPRODUCED")], False) == (False, False)


def test_case_record_uses_exact_verdict_equality_and_no_finding_is_not_reproduced() -> None:
    class Finding:
        verdict = "SUSPECTED"

    record = _case_record(
        type(
            "Case",
            (),
            {
                "case_id": "case-1",
                "category": "control",
                "expected_finding": True,
                "expected_verdict": "SUSPECTED",
                "expected_vulnerable": False,
            },
        )(),
        [Finding()],
    )
    assert record["actual_verdict"] == "SUSPECTED"
    assert record["verdict_match"] is True

    no_finding = _case_record(
        type(
            "Case",
            (),
            {
                "case_id": "case-2",
                "category": "control",
                "expected_finding": False,
                "expected_verdict": "NOT_REPRODUCED",
                "expected_vulnerable": False,
            },
        )(),
        [],
    )
    assert no_finding["actual_verdict"] == "NOT_REPRODUCED"
    assert no_finding["verdict_match"] is True


def test_expanded_labeled_evaluation_reports_metrics_without_tuning() -> None:
    assert len(EVALUATION_CASES) == 100
    assert len({case.case_id for case in EVALUATION_CASES}) == 100

    detectors = (
        PromptInjectionDetector(),
        JailbreakDetector(),
        DataLeakageDetector(),
        ResponseIntegrityDetector(),
    )
    aggregator = DetectionAggregator()
    records: list[dict[str, object]] = []
    detector_runtime_ms = 0.0

    for case in EVALUATION_CASES:
        result = _result(case)
        started = time.perf_counter()
        raw_findings = []
        for detector in detectors:
            raw_findings.extend(asyncio.run(detector.detect(result)))
        detector_runtime_ms += (time.perf_counter() - started) * 1000
        findings = aggregator.aggregate_vulnerabilities(raw_findings)
        records.append(_case_record(case, findings))

    overall = _records_metrics(records)
    category_rows: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        category_rows[str(record["category"])].append(record)
    confirmed_security = _metrics(
        [
            (
                record["actual_verdict"] == "CONFIRMED",
                bool(record["expected_vulnerable"]),
            )
            for record in records
            if record["category"]
            not in {"base64_incorrect_decode", "base64_safe_refusal", "truncated_response"}
        ]
    )
    actual_verdict_counts = defaultdict(int)
    expected_verdict_counts = defaultdict(int)
    for record in records:
        actual_verdict_counts[str(record["actual_verdict"])] += 1
        expected_verdict_counts[str(record["expected_verdict"])] += 1
    verdict_matches = sum(bool(record["verdict_match"]) for record in records)
    print("\nEXPANDED EVALUATION (100 fixed synthetic cases)")
    print(
        f"Confusion matrix: TP={overall['TP']} FP={overall['FP']} "
        f"TN={overall['TN']} FN={overall['FN']}"
    )
    print(
        f"Precision={overall['precision']:.2%} Recall={overall['recall']:.2%} "
        f"F1={overall['f1']:.4f} FPR={overall['fpr']:.2%} FNR={overall['fnr']:.2%}"
    )
    print(
        "Confirmed-vulnerability metrics (security cases only; CONFIRMED only): "
        f"{confirmed_security}"
    )
    print(f"Detector runtime (excluding model inference): {detector_runtime_ms:.2f} ms")
    print(f"Actual verdict counts: {dict(sorted(actual_verdict_counts.items()))}")
    print(f"Expected verdict counts: {dict(sorted(expected_verdict_counts.items()))}")
    print(f"Exact verdict matches: {verdict_matches}/100")
    print("Case-level results:")
    for record in records:
        print(
            f"{record['test_case_id']} expected_finding={record['expected_finding']} "
            f"expected_verdict={record['expected_verdict']} "
            f"actual_finding={record['actual_finding']} "
            f"actual_verdict={record['actual_verdict']} "
            f"match={record['verdict_match']}"
        )
    for category, category_data in sorted(category_rows.items()):
        print(f"{category}: {_records_metrics(category_data)}")
