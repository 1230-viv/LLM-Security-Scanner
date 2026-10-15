from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attack_library.repository import AttackPromptRepository
from app.schemas.attack import AttackPrompt


def test_curated_test_suite_discovered_and_loaded() -> None:
    repository = AttackPromptRepository()
    test_cases = repository.get_test_cases()

    # Verify curated items exist
    sec_ids = [t.id for t in test_cases if t.id.startswith("SEC-") or t.id.startswith("CTRL-")]
    assert len(sec_ids) >= 10
    assert "SEC-SYS-001" in sec_ids
    assert "CTRL-SYS-001" in sec_ids


def test_curated_cases_conform_to_rich_schema() -> None:
    repository = AttackPromptRepository()
    curated_cases = [t for t in repository.get_test_cases() if t.id.startswith("SEC-")]

    for case in curated_cases:
        assert case.id
        assert case.category
        assert case.prompt_text
        assert case.attack_input == case.prompt_text
        assert case.security_property
        assert case.technique
        assert case.success_criterion
        assert case.expected_secure_behavior
        assert case.reference_label == "attack"
        assert not case.is_benign_control


def test_benign_controls_conformance() -> None:
    repository = AttackPromptRepository()
    controls = repository.get_benign_controls()

    assert len(controls) >= 6
    for ctrl in controls:
        assert ctrl.id.startswith("CTRL-")
        assert ctrl.is_benign_control is True
        assert ctrl.reference_label == "benign_control"
        assert ctrl.security_property


def test_duplicate_prompt_id_raises_value_error(tmp_path: Path) -> None:
    # Create a temp directory with duplicate prompt IDs in JSON
    dupe_file = tmp_path / "duplicates.json"
    data = [
        {"id": "DUPE-01", "category": "instruction_override", "prompt_text": "First"},
        {"id": "DUPE-01", "category": "instruction_override", "prompt_text": "Second"},
    ]
    dupe_file.write_text(json.dumps(data), encoding="utf-8")

    repo = AttackPromptRepository(prompt_dir=tmp_path)
    with pytest.raises(ValueError, match="Duplicate prompt ID detected: 'DUPE-01'"):
        repo.count_prompts()
