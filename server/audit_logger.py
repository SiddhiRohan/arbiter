"""
Arbiter — Audit Logger
Non-blocking, thread-safe audit pipeline using QueueHandler + QueueListener.
Three destinations: file (.jsonl), in-memory (API), console (terminal).
All entries are PII-scrubbed before writing.
"""

import copy
import json
import logging
import logging.handlers
import queue
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
AUDIT_LOG_FILE = LOG_DIR / "audit_log.jsonl"

_SSN_RE = re.compile(r"\d{3}-\d{2}-\d{4}")
_SENSITIVE_KEYS = frozenset({"ssn", "social_security", "social_security_number"})
_FINANCIAL_KEYS = frozenset({"annual_salary", "amount_due", "amount_paid", "balance"})


def scrub_pii(data: dict) -> dict:
    """Deep-copy and redact PII from a dict before it hits any log target."""
    cleaned = copy.deepcopy(data)

    def _walk(obj):
        if isinstance(obj, dict):
            for key in obj:
                lowered = key.lower()
                if lowered in _SENSITIVE_KEYS:
                    obj[key] = "[REDACTED]"
                elif lowered in _FINANCIAL_KEYS:
                    obj[key] = "[REDACTED-FINANCIAL]"
                elif isinstance(obj[key], str):
                    obj[key] = _SSN_RE.sub("[REDACTED-SSN]", obj[key])
                else:
                    _walk(obj[key])
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = _SSN_RE.sub("[REDACTED-SSN]", item)
                else:
                    _walk(item)

    _walk(cleaned)
    return cleaned


# ── Handler: write to .jsonl file ──
class _FileTarget(logging.Handler):
    def __init__(self, filepath: Path):
        super().__init__()
        self.filepath = filepath

    def emit(self, record):
        entry = getattr(record, "audit_entry", None)
        if not entry:
            return
        try:
            scrubbed = scrub_pii(entry)
            with open(self.filepath, "a") as f:
                f.write(json.dumps(scrubbed, default=str) + "\n")
        except Exception:
            self.handleError(record)


# ── Handler: append to in-memory list (serves the API) ──
_memory_store: list[dict] = []


class _MemoryTarget(logging.Handler):
    def emit(self, record):
        entry = getattr(record, "audit_entry", None)
        if not entry:
            return
        try:
            _memory_store.append(scrub_pii(entry))
        except Exception:
            self.handleError(record)


# ── Handler: pretty-print to terminal ──
class _ConsoleTarget(logging.Handler):
    def emit(self, record):
        entry = getattr(record, "audit_entry", None)
        if not entry:
            return
        try:
            sep = "=" * 60
            session = entry.get("session_context", {})
            print(f"\n{sep}")
            print(f"  AUDIT — {entry['trace_id']}")
            print(sep)
            print(f"  Tenant    : {entry.get('tenant_id', 'N/A')}")
            print(f"  Timestamp : {entry['timestamp']}")
            print(f"  User      : {entry['user_id']} | Role: {entry['role']} | Clearance: {entry['clearance']}")
            print(f"  Session   : {session.get('session_id', 'N/A')}")
            print(f"  Model     : {entry['model_invoked']}")
            print(f"  Decision  : {entry['policy_decision']}")
            print(f"  Accessed  : {entry['resources_accessed']}")
            print(f"  Denied    : {entry['resources_denied']}")
            print(f"  Masked    : {entry['fields_masked']}")
            print(f"  TTL       : {entry.get('ttl_status', {})}")
            print(f"  Explain   : {entry['explanation']}")
            print(sep)
        except Exception:
            self.handleError(record)


# ── Wire up the queue-based pipeline ──
_queue = queue.Queue(-1)
_logger = logging.getLogger("arbiter.audit")
_logger.setLevel(logging.INFO)
_logger.propagate = False
_logger.addHandler(logging.handlers.QueueHandler(_queue))

_listener = logging.handlers.QueueListener(
    _queue,
    _FileTarget(AUDIT_LOG_FILE),
    _MemoryTarget(),
    _ConsoleTarget(),
    respect_handler_level=True,
)
_listener.start()


def log_entry(
    trace_id: str,
    tenant_id: str,
    identity_scope: dict,
    session_context: dict,
    model_id: str,
    resources_accessed: list[str],
    resources_denied: list[str],
    fields_masked: list[str],
    policy_decision: str,
    explanation: str,
    ttl_status: dict,
) -> dict:
    """Create and dispatch an audit entry through the pipeline."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trace_id": trace_id,
        "tenant_id": tenant_id,
        "user_id": identity_scope["user_id"],
        "role": identity_scope["role"],
        "clearance": identity_scope["clearance"],
        "session_context": {
            "session_id": session_context.get("session_id", ""),
            "ip_address": session_context.get("ip_address", ""),
            "request_timestamp": session_context.get("request_timestamp", ""),
        },
        "model_invoked": model_id,
        "resources_accessed": resources_accessed,
        "resources_denied": resources_denied,
        "fields_masked": fields_masked,
        "policy_decision": policy_decision,
        "explanation": explanation,
        "ttl_status": ttl_status,
    }

    record = logging.LogRecord(
        name="arbiter.audit", level=logging.INFO,
        pathname="", lineno=0, msg="audit", args=(), exc_info=None,
    )
    record.audit_entry = entry
    _logger.handle(record)
    return entry


def get_all_entries() -> list[dict]:
    return _memory_store


def get_entry_by_trace(trace_id: str) -> Optional[dict]:
    for entry in _memory_store:
        if entry["trace_id"] == trace_id:
            return entry
    return None


def shutdown():
    _listener.stop()
