
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
