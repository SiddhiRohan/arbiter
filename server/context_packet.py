"""
Arbiter — Context Packet (CCP v2.0)
Every LLM invocation is wrapped in a Context Packet that documents:
- Who requested it (identity scope)
- What model is being used (model descriptor)
- What data was authorized/denied/masked (context constraints)
- The policy hash for reproducibility

v2.0 additions over v1.0:
- Tenant context (multi-org support)
- Data source metadata (origin tracking)
- Resource descriptors with TTL status
"""

import hashlib
import json
from datetime import datetime, timezone


def build_packet(
    trace_id: str,
    tenant_id: str,
    identity_scope: dict,
    model_config: dict,
    authorized_resources: list[str],
    denied_resources: list[str],
    mask_fields: list[str],
    denial_reasons: list[dict],
    policy_decision: str,
    resource_descriptors: dict,
    ttl_status: dict,
    policies_snapshot: dict,
) -> dict:
    """
    Construct a CCP v2.0 Context Packet for a single LLM invocation.
    This packet is stored and available via API for compliance review.
    """
    # Hash the policy state for tamper detection / reproducibility
    policy_str = json.dumps(policies_snapshot, sort_keys=True)
    policy_hash = "sha256:" + hashlib.sha256(policy_str.encode()).hexdigest()[:16]

    return {
        "ccp_version": "2.0",
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "tenant": {
            "tenant_id": tenant_id,
        },

        "identity_scope": {
            "user_id": identity_scope["user_id"],
            "role": identity_scope["role"],
            "clearance": identity_scope["clearance"],
            "session_context": identity_scope.get("session_context", {}),
        },

        "selected_model": {
            "model_id": model_config.get("model_id", "unknown"),
            "provider": model_config.get("provider", "unknown"),
            "compliance": model_config.get("compliance", "none"),
            "risk_level": model_config.get("risk_level", "unknown"),
        },

        "authorized_resources": [
            {
                "resource_id": r,
                "descriptor": resource_descriptors.get(r, {}),
                "ttl_status": ttl_status.get(r, {}),
            }
            for r in authorized_resources
        ],

        "context_constraints": {
            "mask_fields": mask_fields,
            "denied_resources": denied_resources,
            "denial_reasons": denial_reasons,
        },

        "policy_decision": policy_decision,
        "policy_hash": policy_hash,
    }
