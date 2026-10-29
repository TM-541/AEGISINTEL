"""Argon2id password hashing and password policy."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from threatlens.errors import ValidationFailedError

# argon2-cffi defaults to Argon2id with the RFC 9106 low-memory profile.
_hasher = PasswordHasher()
# Used when the username does not exist, so the response time does not reveal that.
_DUMMY_HASH = _hasher.hash("threatlens-timing-equaliser")

MIN_LENGTH = 12
MAX_LENGTH = 128
_COMMON = {
    "password1234",
    "passwordpassword",
    "123456789012",
    "qwertyuiop12",
    "letmein12345",
    "administrator",
    "welcome12345",
    "changeme1234",
    "iloveyou1234",
}


def validate_password_policy(password: str, *, username: str = "") -> None:
    problems = []
    if not MIN_LENGTH <= len(password) <= MAX_LENGTH:
        problems.append(f"Password must be {MIN_LENGTH}-{MAX_LENGTH} characters.")
    if password.lower() in _COMMON or len(set(password)) < 5:
        problems.append("Password is too common or too repetitive.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain the username.")
    if problems:
        raise ValidationFailedError(" ".join(problems))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)
