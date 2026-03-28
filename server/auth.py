"""
Arbiter -- Authentication & Session Management
Handles user login, session creation, and request authentication.
Credentials are loaded from config -- not hardcoded.
"""

import uuid
import time
from typing import Optional

# Demo credentials -- in production this would be a database or SSO integration
# Keyed by username, maps to user_id, role, and display label
DEMO_CREDENTIALS = {
    "admin": {
        "password": "admin",
        "user_id": "P003",
        "role": "Admin",
        "label": "Robert Torres",
    },
    "teacher": {
        "password": "teacher",
        "user_id": "P002",
        "role": "Teacher",
        "label": "Sarah Chen",
    },
    "student": {
        "password": "student",
        "user_id": "P001",
        "role": "Student",
        "label": "Alex Rivera",
    },
}

# In-memory session store -- maps session_id to user info + expiry
_sessions: dict[str, dict] = {}
SESSION_TTL_SECONDS = 3600  # 1 hour


def authenticate(username: str, password: str) -> Optional[dict]:
    """
    Verify credentials and create a session.
    Returns session info dict on success, None on failure.
    """
    username = username.strip().lower()
    cred = DEMO_CREDENTIALS.get(username)

    if not cred or cred["password"] != password:
        return None

    session_id = f"sess-{uuid.uuid4().hex[:12]}"
    session = {
        "session_id": session_id,
        "user_id": cred["user_id"],
        "role": cred["role"],
        "label": cred["label"],
        "username": username,
        "created_at": time.time(),
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }

    _sessions[session_id] = session
    return session


def validate_session(session_id: str) -> Optional[dict]:
    """
    Check if a session is valid and not expired.
    Returns session dict if valid, None otherwise.
    """
    session = _sessions.get(session_id)
    if not session:
        return None

    if time.time() > session["expires_at"]:
        _sessions.pop(session_id, None)
        return None

    return session


def destroy_session(session_id: str) -> bool:
    """Remove a session (logout). Returns True if session existed."""
    return _sessions.pop(session_id, None) is not None


def get_active_sessions() -> list[dict]:
    """List all active sessions (for admin dashboard)."""
    now = time.time()
    active = []
    expired_keys = []

    for sid, session in _sessions.items():
        if now > session["expires_at"]:
            expired_keys.append(sid)
        else:
            active.append({
                "session_id": sid,
                "user_id": session["user_id"],
                "role": session["role"],
                "label": session["label"],
                "created_at": session["created_at"],
                "expires_at": session["expires_at"],
            })

    for key in expired_keys:
        _sessions.pop(key, None)

    return active


def get_demo_roles() -> list[dict]:
    """Return available demo roles for the login screen."""
    return [
        {
            "username": username,
            "user_id": cred["user_id"],
            "role": cred["role"],
            "label": cred["label"],
        }
        for username, cred in DEMO_CREDENTIALS.items()
    ]
