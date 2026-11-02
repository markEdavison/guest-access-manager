
import hashlib
import secrets
import time

SESSION_LIFETIME = 8 * 60 * 60


def create_session():
    """Generate a cryptographically random session token."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    expires_at = int(time.time()) + SESSION_LIFETIME

    return token, token_hash, expires_at


def hash_session_token(token):
    """Hash a session token before comparing it with stored data."""
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def session_is_valid(expires_at):
    """Check whether a session has expired."""
    return int(time.time()) < int(expires_at)

def save_session(user_id):
    """Create and store a staff login session."""
    from database import get_connection

    token, token_hash, expires_at = create_session()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO staff_sessions
                (token_hash, user_id, expires_at)
            VALUES (?, ?, ?)
            """,
            (token_hash, user_id, expires_at)
        )

    return token


def get_session_user(token):
    """Return the active user associated with a valid session."""
    from database import get_connection

    if not token:
        return None

    token_hash = hash_session_token(token)

    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT u.id, u.username, u.role
            FROM staff_sessions AS s
            JOIN staff_users AS u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.expires_at > ?
              AND u.active = 1
            """,
            (token_hash, int(time.time()))
        ).fetchone()

    return dict(user) if user else None


def delete_session(token):
    """Invalidate a session during logout."""
    from database import get_connection

    if not token:
        return

    with get_connection() as connection:
        connection.execute(
            "DELETE FROM staff_sessions WHERE token_hash = ?",
            (hash_session_token(token),)
        )
