
import hashlib
import hmac
import os
import secrets


def hash_password(password, salt=None):
    """Hash a password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = secrets.token_bytes(16)

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600_000
    )

    return f"{salt.hex()}:{derived_key.hex()}"


def verify_password(password, stored_hash):
    """Verify a password without exposing the stored hash."""
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            600_000
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError):
        return False
