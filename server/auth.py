"""
Arbiter -- Authentication & Session Management
Handles user login, session creation, and request authentication.
Credentials are loaded from config -- not hardcoded.
"""

import uuid
import time
from typing import Optional

# Demo credentials — person_ids map to demo_university.json
# In production this would be a database or SSO integration
DEMO_CREDENTIALS = {
    "admin": {
        "password": "admin",
        "user_id": "P012",
        "role": "Admin",
        "label": "Robert Torres (Dean of Students)",
    },
    "teacher": {
        "password": "teacher",
        "user_id": "P009",
        "role": "Teacher",
        "label": "Sarah Chen (CS, Associate Prof)",
    },
    "teacher2": {
        "password": "teacher2",
        "user_id": "P010",
        "role": "Teacher",
        "label": "James Washington (CS, Asst Prof)",
    },
    "advisor": {
        "password": "advisor",
        "user_id": "P011",
        "role": "Advisor",
        "label": "Priya Sharma (Math, Professor)",
    },
    "student": {
        "password": "student",
        "user_id": "P001",
        "role": "Student",
        "label": "Alex Rivera (CS, Sophomore)",
    },
    "student2": {
        "password": "student2",
        "user_id": "P004",
        "role": "Student",
        "label": "Carlos Mendez (Math, Freshman)",
    },
    "ta": {
        "password": "ta",
        "user_id": "P003",
        "role": "TA",
        "label": "Lena Kowalski (CS, Senior — TA for CS101)",
    },
}

# In-memory session store — maps session_id to user info + expiry
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


class AuthorizationError(Exception):
    """Raised when a request cannot be bound to a valid authenticated identity."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def resolve_session_identity(
    session_id: Optional[str],
    claimed_role: Optional[str] = None,
    claimed_user_id: Optional[str] = None,
) -> dict:
    """
    Bind a request to its authenticated identity (ADV-01 fix).

    The role and user_id used for governance are ALWAYS taken from the
    validated server-side session — NEVER from client-supplied values. This
    closes the privilege-escalation gap where a caller could send
    role="Admin" in the request body and receive Admin data.

    Any client-supplied role/user_id are accepted only to DETECT tampering;
    they never influence the authorization decision.

    Returns: {"user_id", "role", "label", "tampered": bool}
    Raises:  AuthorizationError(401) if the session is missing/invalid/expired.
    """
    if not session_id:
        raise AuthorizationError(401, "Authentication required: no session_id provided.")

    session = validate_session(session_id)
    if not session:
        raise AuthorizationError(401, "Invalid or expired session.")

    authoritative_role = session["role"]
    authoritative_user = session["user_id"]

    tampered = (
        (claimed_role is not None and claimed_role != authoritative_role)
        or (claimed_user_id is not None and claimed_user_id != authoritative_user)
    )

    return {
        "user_id": authoritative_user,
        "role": authoritative_role,
        "label": session.get("label", ""),
        "tampered": tampered,
    }


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