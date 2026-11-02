
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

def create_staff_user(username, password):
    """Create a staff user with a securely hashed password."""
    from database import get_connection

    if not username or not password:
        raise ValueError("Username and password are required.")

    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")

    password_hash = hash_password(password)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO staff_users
                (username, password_hash, role)
            VALUES (?, ?, 'frontdesk')
            """,
            (username, password_hash)
        )
        return cursor.lastrowid

def authenticate_staff_user(username, password):
    """Verify an active staff user's credentials."""
    from database import get_connection

    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, password_hash, role
            FROM staff_users
            WHERE username = ? AND active = 1
            """,
            (username,)
        ).fetchone()

    if user is None:
        return None

    if not verify_password(password, user["password_hash"]):
        return None

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }

def login_is_rate_limited(username, source_ip):
    """Limit failed login attempts to five per 15 minutes."""
    import time
    from database import get_connection

    cutoff = int(time.time()) - 900

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failures
            FROM login_attempts
            WHERE username = ?
              AND source_ip = ?
              AND attempted_at >= ?
              AND successful = 0
            """,
            (username, source_ip, cutoff)
        ).fetchone()

    return row["failures"] >= 5

def record_login_attempt(username, source_ip, successful):
    """Record a staff login attempt for security monitoring."""
    import time
    from database import get_connection

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO login_attempts
                (username, source_ip, attempted_at, successful)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                source_ip,
                int(time.time()),
                1 if successful else 0
            )
        )

def ip_is_rate_limited(source_ip):
    """Limit an IP address to 20 failed logins per 15 minutes."""
    import time
    from database import get_connection

    cutoff = int(time.time()) - 900

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failures
            FROM login_attempts
            WHERE source_ip = ?
              AND attempted_at >= ?
              AND successful = 0
            """,
            (source_ip, cutoff)
        ).fetchone()

    return row["failures"] >= 20

def create_csrf_token():
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(submitted_token, expected_token):
    """Compare CSRF tokens securely."""
    if not submitted_token or not expected_token:
        return False

    return hmac.compare_digest(
        submitted_token,
        expected_token
    )
