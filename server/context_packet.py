"""
Arbiter — Context Packet (CCP v3.0)
Every LLM invocation is wrapped in a Context Packet that documents:
- Who requested it (identity scope)
- What model is being used (model descriptor)
- What data was authorized/denied/masked (context constraints)
- What inference channels were detected and blocked
- What output violations were caught after the LLM responded
- The policy hash for reproducibility

v3.0 additions over v2.0:
- Inference control section (channels blocked, fields withheld)
- Output governance section (violations, sanitization decision)
- Bidirectional policy hash (covers input + output decisions)
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Optional


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
    inference_channels_blocked: Optional[list[dict]] = None,
) -> dict:
    """
    Construct a CCP v3.0 Context Packet for a single LLM invocation.
    This packet is stored and available via API for compliance review.
    Output governance is attached later via attach_output_governance().
    """
    # Hash the policy state for tamper detection / reproducibility
    policy_str = json.dumps(policies_snapshot, sort_keys=True)
    policy_hash = "sha256:" + hashlib.sha256(policy_str.encode()).hexdigest()[:16]

    return {
        "ccp_version": "3.0",
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

        "input_governance": {
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
        },

        "inference_control": {
            "channels_blocked": inference_channels_blocked or [],
            "fields_withheld": [
                ch["withheld_field"]
                for ch in (inference_channels_blocked or [])
            ],
            "total_blocked": len(inference_channels_blocked or []),
        },

        "output_governance": {
            "violations": [],
            "decision": "pending",
            "scan_timestamp": None,
        },

        "policy_hash": policy_hash,
    }


def attach_output_governance(packet: dict, scan_result: dict) -> dict:
    """
    Attach output governance results to an existing context packet.
    Called after the LLM responds and the output scanner runs.
    Updates the policy hash to cover both input + output decisions.
    """
    packet["output_governance"] = {
        "violations": scan_result.get("violations", []),
        "decision": scan_result.get("decision", "clean"),
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_violations": len(scan_result.get("violations", [])),
    }

    # Rehash to cover both input and output governance
    combined = json.dumps({
        "input": packet.get("input_governance", {}),
        "inference": packet.get("inference_control", {}),
        "output": packet["output_governance"],
    }, sort_keys=True, default=str)
    packet["policy_hash_bidirectional"] = (
        "sha256:" + hashlib.sha256(combined.encode()).hexdigest()[:16]
    )

    return packet