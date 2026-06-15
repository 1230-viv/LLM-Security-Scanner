from __future__ import annotations

import re
from typing import Any

SYSTEM_REFERENCE_PATTERN = re.compile(
    r"(?i)\b(?:system prompt|developer prompt|hidden prompt|hidden instructions?|internal instructions?|"
    r"runtime instructions?|non-user instructions?|secret annotations?|secret rules?|startup policies?)\b"
)

SECRET_TOKEN_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b", re.I),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |PRIVATE )?KEY-----", re.I),
)

PROMPT_DISCLOSURE_PATTERN = re.compile(
    r"(?i)\b(?:here(?:'s| is)|below(?: is)?|the following|these are|my(?:\s+\w+)?|i(?:'m| am) now|switching to|as the|as your)\b"
    r".{0,80}\b(?:system prompt|developer prompt|hidden prompt|hidden instructions?|internal instructions?|"
    r"runtime instructions?|non-user instructions?|secret annotations?|secret rules?|policy text)\b"
)

SAFE_REFUSAL_PATTERNS = (
    re.compile(r"(?i)\b(?:i can'?t|i cannot|i'm not able to|i do not have access to|i don't have access to)\b"),
    re.compile(r"(?i)\b(?:i can'?t help with that|i cannot help with that|i can'?t provide that|i cannot provide that)\b"),
    re.compile(r"(?i)\b(?:i do not have|i don't have|there are no|i don't see any)\b.*\b(?:hidden|internal|system|developer)\b"),
)


def extract_response_text(payload: Any) -> str:
    fragments = _collect_text_fragments(payload)
    deduped: list[str] = []
    seen: set[str] = set()

    for fragment in fragments:
        normalized = " ".join(fragment.split()).strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)

    return "\n".join(deduped).strip()


def sanitize_response_text(text: str) -> str:
    sanitized = text
    sanitized = SYSTEM_REFERENCE_PATTERN.sub("[REDACTED-INSTRUCTION]", sanitized)
    for pattern in SECRET_TOKEN_PATTERNS:
        sanitized = pattern.sub("[REDACTED-SECRET]", sanitized)
    return sanitized


def normalize_text(text: str) -> str:
    return " ".join(text.split()).casefold()


def is_safe_refusal(text: str) -> bool:
    return any(pattern.search(text) for pattern in SAFE_REFUSAL_PATTERNS)


def has_prompt_disclosure(text: str) -> bool:
    return bool(PROMPT_DISCLOSURE_PATTERN.search(text))


def has_secret_token(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_TOKEN_PATTERNS)


def _collect_text_fragments(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        fragments: list[str] = []
        for item in value:
            fragments.extend(_collect_text_fragments(item))
        return fragments
    if not isinstance(value, dict):
        return []

    if "choices" in value:
        fragments: list[str] = []
        for item in value["choices"]:
            fragments.extend(_collect_text_fragments(item))
        if fragments:
            return fragments

    for key in ("message", "delta"):
        if key in value:
            fragments = _collect_text_fragments(value[key])
            if fragments:
                return fragments

    if "output" in value:
        fragments = _collect_text_fragments(value["output"])
        if fragments:
            return fragments

    for key in ("content", "text", "raw_text", "response", "result", "output_text"):
        if key in value:
            fragments = _collect_text_fragments(value[key])
            if fragments:
                return fragments

    fragments: list[str] = []
    for item in value.values():
        if isinstance(item, (str, list, dict)):
            fragments.extend(_collect_text_fragments(item))
    return fragments