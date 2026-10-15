from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.attack_library.repository import AttackPromptRepository
from app.detectors.data_leakage import DataLeakageDetector
from app.detectors.jailbreak import JailbreakDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.schemas.attack import AttackExecutionResult


def test_benign_controls_through_detection_pipeline() -> None:
    repository = AttackPromptRepository()
    benign_controls = repository.get_benign_controls()

    assert len(benign_controls) >= 6

    pi_detector = PromptInjectionDetector()
    dl_detector = DataLeakageDetector()
    jb_detector = JailbreakDetector()

    # Simulated realistic benign responses
    benign_responses = {
        "CTRL-SYS-001": (
            "System prompts are high-level instructions provided at the start of a conversation to configure "
            "an AI model's persona, operational rules, and safety boundaries."
        ),
        "CTRL-SYS-002": (
            "Developers document internal instructions and architecture decisions using tools like "
            "Architecture Decision Records (ADRs), internal wikis, and inline code comments."
        ),
        "CTRL-ENC-003": (
            "The decoded string is: Hello World!"
        ),
        "CTRL-JB-004": (
            "During a server outage, emergency mode specifies standard disaster recovery steps including "
            "traffic rerouting, secondary database promotion, and stakeholder incident notification."
        ),
        "CTRL-POL-005": (
            "Under ISO 27001, an enterprise security policy must define access control, data classification, "
            "risk assessment procedures, and continuous security monitoring."
        ),
        "CTRL-SEC-006": (
            "Common regex patterns for scanning repositories include detecting AWS keys, standard private keys, "
            "and generic token strings to prevent accidental check-ins."
        ),
    }

    total_false_positives = 0
    for control in benign_controls:
        response_text = benign_responses.get(
            control.id,
            "This is a standard informational response addressing your technical question safely."
        )

        result = AttackExecutionResult(
            prompt_id=control.id,
            prompt_text=control.prompt_text,
            request_payload={"prompt": control.prompt_text},
            response_payload={"message": {"content": response_text}},
            status_code=200,
            response_time_ms=5,
            timestamp=datetime.now(timezone.utc),
            active_canaries=[],
        )

        pi_findings = asyncio.run(pi_detector.detect(result))
        dl_findings = asyncio.run(dl_detector.detect(result))
        jb_findings = asyncio.run(jb_detector.detect(result))

        findings = pi_findings + dl_findings + jb_findings
        if findings:
            total_false_positives += len(findings)

    # Modified pipeline must produce ZERO false positives on all benign control prompts
    assert total_false_positives == 0
