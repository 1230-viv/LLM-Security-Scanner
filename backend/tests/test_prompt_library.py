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
