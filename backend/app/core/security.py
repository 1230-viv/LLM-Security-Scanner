from __future__ import annotations

import hashlib
from base64 import urlsafe_b64encode
from functools import lru_cache

from cryptography.fernet import Fernet

from app.core.settings import get_settings


@lru_cache
def _fernet() -> Fernet:
    settings = get_settings()
    key = settings.resolved_encryption_key.strip()

    try:
        return Fernet(key.encode("utf-8"))
    except Exception:  # noqa: BLE001
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        derived = urlsafe_b64encode(digest)
        return Fernet(derived)


def encrypt_api_key(plain_text: str | None) -> bytes | None:
    if not plain_text:
        return None
    return _fernet().encrypt(plain_text.encode("utf-8"))


def decrypt_api_key(cipher_text: bytes | None) -> str | None:
    if not cipher_text:
        return None
    return _fernet().decrypt(cipher_text).decode("utf-8")
