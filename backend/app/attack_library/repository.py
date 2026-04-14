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
        ordered_categories = list(dict.fromkeys(categories))
        category_set = set(ordered_categories)

        filtered = [prompt for prompt in prompts if prompt.category in category_set]
        if limit is None or limit >= len(filtered):
            return filtered

        prompts_by_category: dict[str, list[AttackPrompt]] = {
            category: [] for category in ordered_categories
        }
        for prompt in filtered:
            prompts_by_category[prompt.category].append(prompt)

        selected: list[AttackPrompt] = []
        category_indexes = {category: 0 for category in ordered_categories}

        # Round-robin keeps smaller scans representative across selected categories.
        while len(selected) < limit:
            progressed = False
            for category in ordered_categories:
                index = category_indexes[category]
                bucket = prompts_by_category.get(category, [])
                if index >= len(bucket):
                    continue

                selected.append(bucket[index])
                category_indexes[category] = index + 1
                progressed = True

                if len(selected) >= limit:
                    break

            if not progressed:
                break

        return selected

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
