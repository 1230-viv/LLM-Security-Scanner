from __future__ import annotations

import json
from pathlib import Path

from app.schemas.attack import AttackPrompt

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"


class AttackPromptRepository:
    """Loads and validates attack prompts from JSON files."""

    def __init__(self, prompt_dir: Path | None = None) -> None:
        self.prompt_dir = prompt_dir or PROMPT_DIR
        self._prompts: list[AttackPrompt] | None = None

    def _load_all(self) -> list[AttackPrompt]:
        if self._prompts is not None:
            return self._prompts

        prompts: list[AttackPrompt] = []
        for file_path in sorted(self.prompt_dir.glob("*.json")):
            with file_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)

            if not isinstance(payload, list):
                raise ValueError(f"Prompt file {file_path.name} must contain a JSON array")

            for item in payload:
                prompts.append(AttackPrompt.model_validate(item))

        self._prompts = prompts
        return prompts

    def load_prompts(self, categories: list[str], limit: int | None = None) -> list[AttackPrompt]:
        prompts = self._load_all()
        category_set = set(categories)

        filtered = [prompt for prompt in prompts if prompt.category in category_set]
        if limit is not None:
            return filtered[:limit]
        return filtered

    def get_prompt_by_id(self, prompt_id: str) -> AttackPrompt:
        prompts = self._load_all()
        for prompt in prompts:
            if prompt.id == prompt_id:
                return prompt
        raise KeyError(f"Prompt not found: {prompt_id}")

    def get_categories(self) -> list[str]:
        prompts = self._load_all()
        return sorted({prompt.category for prompt in prompts})

    def count_prompts(self) -> int:
        return len(self._load_all())
