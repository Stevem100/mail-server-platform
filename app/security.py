"""Secrets: API keys (hashed, shown once), Argon2 password hashing, DKIM key encryption.

- Admin keys start with mk_, account keys with ak_ (stored as SHA-256 hashes).
- SMTP credential passwords are hashed with Argon2 (per the security table).
- DKIM private keys are encrypted with Fernet before storage/upload (app key from APP_SECRET).
"""

import base64
import hashlib
import secrets
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

from .config import settings

_ph = PasswordHasher()


# --- API keys ---------------------------------------------------------------

def generate_api_key(is_admin: bool) -> tuple[str, str]:
    """Return (plaintext_key, sha256_hash). The plaintext is shown exactly once."""
    prefix = "mk_" if is_admin else "ak_"
    key = prefix + secrets.token_urlsafe(30)
    return key, hash_api_key(key)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# --- Passwords (SMTP credentials, mailboxes) --------------------------------

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, ValueError):
        return False


def generate_password(length: int = 24) -> str:
    return secrets.token_urlsafe(length)[:length]


# --- DKIM private key encryption --------------------------------------------

@lru_cache
def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.app_secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()


# --- Misc tokens ------------------------------------------------------------

def verification_token() -> str:
    return secrets.token_urlsafe(24)


def webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(24)


def object_id() -> str:
    return secrets.token_hex(12)
