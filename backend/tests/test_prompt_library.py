from collections import Counter

from app.attack_library.repository import AttackPromptRepository


def test_prompt_library_has_minimum_volume() -> None:
    repository = AttackPromptRepository()
    assert repository.count_prompts() >= 200


def test_prompt_categories_are_available() -> None:
    repository = AttackPromptRepository()
    categories = repository.get_categories()

    assert "instruction_override" in categories
    assert "role_confusion" in categories
    assert "data_exfiltration" in categories
    assert "hidden_instruction_extraction" in categories


def test_prompt_limit_round_robin_distribution() -> None:
    repository = AttackPromptRepository()
    categories = [
        "instruction_override",
        "role_confusion",
        "data_exfiltration",
        "hidden_instruction_extraction",
    ]

    prompts = repository.load_prompts(categories=categories, limit=100)
    counts = Counter(prompt.category for prompt in prompts)

    assert len(prompts) == 100
    assert counts["instruction_override"] == 25
    assert counts["role_confusion"] == 25
    assert counts["data_exfiltration"] == 25
    assert counts["hidden_instruction_extraction"] == 25
