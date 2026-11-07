"""Argon2id password hashing (argon2-cffi defaults follow RFC 9106 recommendations)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from rasednet.i18n import get_lang, tr

_hasher = PasswordHasher(type=Type.ID)

# Verified against when the username does not exist, so timing does not reveal valid users.
_DUMMY_HASH = _hasher.hash("rasednet-dummy-password-for-timing-equalisation")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_policy_errors(password: str, username: str, min_length: int) -> list[str]:
    errors: list[str] = []
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters" if get_lang()=="en" else f"يجب ألا تقل كلمة المرور عن {min_length} حرفاً")
    if len(password) > 256:
        errors.append(tr("كلمة المرور طويلة جداً", "Password is too long"))
    if username and username.lower() in password.lower():
        errors.append(tr("يجب ألا تحتوي كلمة المرور على اسم المستخدم", "Password must not contain the username"))
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        ]
    )
    if classes < 3:
        errors.append(tr("يجب أن تحتوي كلمة المرور على ثلاثة أنواع على الأقل من: أحرف صغيرة، كبيرة، أرقام، رموز", "Password must include at least three of: lowercase, uppercase, digits, symbols"))
    return errors
