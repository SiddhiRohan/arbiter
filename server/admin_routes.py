"""
Arbiter -- Admin & Utility API Routes
Endpoints for:
- Audit log viewing and download
- Context packet retrieval
- Role management (CRUD)
- Policy management
- Demo utilities
"""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from audit_logger import get_all_entries, get_entry_by_trace, AUDIT_LOG_FILE
from policy_engine import (
    PolicyEngine,
    get_full_config,
    update_role,
    delete_role,
    update_policy,
)
from auth import get_demo_roles, get_active_sessions

router = APIRouter()

# In-memory store for context packets (keyed by trace_id)
_context_packets: dict[str, dict] = {}


def store_context_packet(trace_id: str, packet: dict):
    """Called by main.py after each chat request to store the packet."""
    _context_packets[trace_id] = packet


# ============================================================
# AUDIT LOG
# ============================================================

@router.get("/audit-log")
async def get_full_audit_log():
    """View all audit entries (PII-scrubbed)."""
    log = get_all_entries()
    return {"total_entries": len(log), "entries": log}


@router.get("/audit-log/{trace_id}")
async def get_audit_entry(trace_id: str):
    """View a single audit entry by trace ID."""
    entry = get_entry_by_trace(trace_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Trace {trace_id} not found")
    return entry


@router.get("/audit-log-file")
async def download_audit_log_file():
    """Download the raw .jsonl audit log file."""
    if not AUDIT_LOG_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No audit log file yet. Make some queries first.",
        )
    return FileResponse(
        path=str(AUDIT_LOG_FILE),
        filename="audit_log.jsonl",
        media_type="application/json",
    )


# ============================================================
# CONTEXT PACKETS
# ============================================================

@router.get("/context-packet/{trace_id}")
async def get_context_packet(trace_id: str):
    """View the CCP v2.0 Context Packet for a trace."""
    packet = _context_packets.get(trace_id)
    if not packet:
        raise HTTPException(
            status_code=404,
            detail=f"Context packet for {trace_id} not found",
        )
    return packet


@router.get("/context-packets")
async def list_context_packets():
    """List all stored context packets (trace IDs and summaries)."""
    summaries = []
    for trace_id, packet in _context_packets.items():
        summaries.append({
            "trace_id": trace_id,
            "timestamp": packet.get("timestamp"),
            "tenant": packet.get("tenant", {}).get("tenant_id"),
            "decision": packet.get("policy_decision"),
            "user_id": packet.get("identity_scope", {}).get("user_id"),
            "role": packet.get("identity_scope", {}).get("role"),
        })
    return {"total": len(summaries), "packets": summaries}


# ============================================================
# ROLE MANAGEMENT (CRUD)
# ============================================================

class RoleCreateRequest(BaseModel):
    role_name: str
    clearance: str
    description: str
    allowed_resources: list[str]
    mask_overrides: list[str] = []
    can_view_others_financial: bool = False
    can_view_grades: bool = False
    financial_scope: Optional[str] = None


@router.get("/admin/roles")
async def list_roles():
    """List all configured roles."""
    engine = PolicyEngine()
    roles = engine.get_available_roles()
    configs = {}
    for role in roles:
        configs[role] = engine.get_role_config(role)
    return {"roles": configs}


@router.post("/admin/roles")
async def create_role(request: RoleCreateRequest):
    """Create or update a role."""
    role_config = {
        "clearance": request.clearance,
        "description": request.description,
        "allowed_resources": request.allowed_resources,
        "mask_overrides": request.mask_overrides,
        "can_view_others_financial": request.can_view_others_financial,
        "can_view_grades": request.can_view_grades,
    }
    if request.financial_scope:
        role_config["financial_scope"] = request.financial_scope

    update_role(request.role_name, role_config)
    return {"status": "ok", "role": request.role_name, "config": role_config}


@router.delete("/admin/roles/{role_name}")
async def remove_role(role_name: str):
    """Delete a role."""
    success = delete_role(role_name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return {"status": "ok", "deleted": role_name}


# ============================================================
# POLICY MANAGEMENT
# ============================================================

@router.get("/admin/policies")
async def get_policies():
    """View the full policy configuration."""
    return get_full_config()


class PolicyUpdateRequest(BaseModel):
    key: str
    value: list | dict | str


@router.put("/admin/policies")
async def update_policy_endpoint(request: PolicyUpdateRequest):
    """Update a specific institution-level policy setting."""
    update_policy(request.key, request.value)
    return {"status": "ok", "updated": request.key}


@router.get("/admin/resources")
async def list_resources():
    """List all registered resource descriptors."""
    engine = PolicyEngine()
    policies = engine.policies
    return {"resources": policies.get("resources", {})}


# ============================================================
# DEMO UTILITIES
# ============================================================

@router.get("/demo/roles")
async def demo_roles():
    """List available demo login credentials."""
    return {"roles": get_demo_roles()}


@router.get("/admin/sessions")
async def list_sessions():
    """List all active sessions."""
    sessions = get_active_sessions()
    return {"total": len(sessions), "sessions": sessions}


# ============================================================
# CONFIG EXPORT
# ============================================================

@router.get("/admin/config/export")
async def export_config():
    """Export the full configuration for backup or migration."""
    return get_full_config()
