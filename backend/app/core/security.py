"""
CyberShield AI
Password hashing utilities.

JWT creation/validation lives in ``app.core.jwt`` (single source of truth,
driven by ``settings``). This module intentionally contains no secrets.

bcrypt only uses the first 72 BYTES of a password. Silently truncating would
make two different passwords verify as equal, and some bcrypt versions raise
instead. We therefore reject over-long passwords explicitly:

* at the schema layer (clean 422 for register/login), and
* here, as defence in depth, for any other caller.
"""

from passlib.context import CryptContext

BCRYPT_MAX_PASSWORD_BYTES = 72

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

class PasswordTooLongError(ValueError):
    """Raised when a password exceeds bcrypt's 72-byte input limit."""

def password_problem(password: object) -> str | None:
    """
    Return a static, input-free description of why ``password`` cannot be
    used with bcrypt, or ``None`` if it is acceptable.

    The returned text never contains the password itself.
    """
    if not isinstance(password, str):
        return "Password must be a string."

    if "\x00" in password:
        return "Password contains an invalid character."

    try:
        encoded = password.encode("utf-8")
    except UnicodeEncodeError:
        return "Password contains invalid characters."

    if len(encoded) > BCRYPT_MAX_PASSWORD_BYTES:
        return (
            f"Password must be at most {BCRYPT_MAX_PASSWORD_BYTES} bytes "
            "when UTF-8 encoded."
        )

    return None

def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password must not be empty.")

    problem = password_problem(password)

    if problem:
        raise PasswordTooLongError(problem)

    return pwd_context.hash(password)

def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a password. Never raises for bad input: over-long, malformed or
    empty passwords and malformed hashes simply fail verification.
    """
    if not plain_password or not hashed_password:
        return False

    if password_problem(plain_password):
        return False

    try:
        return pwd_context.verify(
            plain_password,
            hashed_password,
        )
    except (ValueError, TypeError):
        return False
