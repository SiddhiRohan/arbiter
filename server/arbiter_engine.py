"""
Arbiter — Core Engine
Orchestrates the full ICCP pipeline for every request:
1. Build identity scope
2. Evaluate policies
3. Filter data based on policy decision
4. Check TTL freshness for each resource
5. Build Context Packet (CCP v2.0)
6. Log the audit entry
7. Return filtered context ready for the LLM

This module is the single entry point — the API layer calls engine.process()
and gets back everything needed to make a governed LLM call.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from policy_engine import PolicyEngine
from data_filter import filter_data, to_text
from context_packet import build_packet
from audit_logger import log_entry

DATA_DIR = Path(__file__).parent.parent / "data"


class ArbiterEngine:
    """
    Stateful engine that processes ICCP-governed requests.
    Tracks resource TTL timestamps across calls.
    """

    def __init__(self, tenant_id: str = "demo_university"):
        self.tenant_id = tenant_id
        self._ttl_timestamps: dict[str, float] = {}
        self._tenant_data: Optional[dict] = None

    def _load_tenant_data(self) -> dict:
        """Load the data source for this tenant. Cached after first load."""
        if self._tenant_data is None:
            data_file = DATA_DIR / f"{self.tenant_id}.json"
            if not data_file.exists():
                raise FileNotFoundError(f"No data source found for tenant: {self.tenant_id}")
            with open(data_file, "r") as f:
                self._tenant_data = json.load(f)
        return self._tenant_data

    def process(
        self,
        user_id: str,
        role: str,
        query: str,
        session_context: Optional[dict] = None,
    ) -> dict:
        """
        Run the complete ICCP pipeline for a single request.

        Returns dict with:
            - filtered_context: text representation of authorized data for the LLM
            - access_level: "full" | "partial" | "denied"
            - masked_fields: list of field names that were masked
            - denied_resources: list of resource IDs that were denied
            - trace_id: unique identifier for this invocation
            - context_packet: full CCP v2.0 packet
        """
        trace_id = f"tr-{uuid.uuid4().hex[:8]}"

        # 1. Build identity scope
        identity = self._build_identity(user_id, role, session_context)

        # 2. Evaluate policies
        policy_engine = PolicyEngine(self.tenant_id)
        policy = policy_engine.evaluate(role, user_id)
        role_config = policy_engine.get_role_config(role) or {}
        model_config = policy_engine.get_model_config()

        # 3. Check TTL freshness for authorized resources
        ttl_status = {}
        resource_descriptors = {}
        for resource_id in policy.authorized_resources:
            descriptor = policy_engine.get_resource_descriptor(resource_id)
            resource_descriptors[resource_id] = descriptor
            ttl_seconds = descriptor.get("ttl_seconds", 300)
            now = time.time()
            elapsed = now - self._ttl_timestamps.get(resource_id, 0)

            if elapsed > ttl_seconds:
                self._ttl_timestamps[resource_id] = now
                ttl_status[resource_id] = {"status": "refreshed", "ttl_seconds": ttl_seconds}
            else:
                remaining = round(ttl_seconds - elapsed)
                ttl_status[resource_id] = {"status": "cached", "remaining_seconds": remaining}

        # 4. Filter data based on policy decision
        tenant_data = self._load_tenant_data()
        filtered = filter_data(
            raw_data=tenant_data,
            policy=policy,
            role=role,
            user_id=user_id,
            role_config=role_config,
        )
        filtered_context = to_text(filtered)

        # 5. Determine access level
        if not policy.authorized_resources:
            access_level = "denied"
        elif policy.denied_resources:
            access_level = "partial"
        else:
            access_level = "full"

        # 6. Build Context Packet (CCP v2.0)
        policies_snapshot = policy_engine.get_full_config() if hasattr(policy_engine, 'get_full_config') else {}
        # Import get_full_config from policy_engine module
        from policy_engine import get_full_config
        policies_snapshot = get_full_config()

        packet = build_packet(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            identity_scope=identity,
            model_config=model_config,
            authorized_resources=policy.authorized_resources,
            denied_resources=policy.denied_resources,
            mask_fields=policy.mask_fields,
            denial_reasons=policy.denial_reasons,
            policy_decision=policy.decision,
            resource_descriptors=resource_descriptors,
            ttl_status=ttl_status,
            policies_snapshot=policies_snapshot,
        )

        # 7. Log the audit entry
        log_entry(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            identity_scope=identity,
            session_context=identity.get("session_context", {}),
            model_id=model_config.get("model_id", "unknown"),
            resources_accessed=policy.authorized_resources,
            resources_denied=policy.denied_resources,
            fields_masked=policy.mask_fields,
            policy_decision=policy.decision,
            explanation=policy.explanation,
            ttl_status=ttl_status,
        )

        return {
            "filtered_context": filtered_context,
            "access_level": access_level,
            "masked_fields": policy.mask_fields,
            "denied_resources": policy.denied_resources,
            "trace_id": trace_id,
            "context_packet": packet,
        }

    def _build_identity(
        self, user_id: str, role: str, session_context: Optional[dict] = None,
    ) -> dict:
        """Construct the identity scope for this request."""
        policy_engine = PolicyEngine(self.tenant_id)
        role_config = policy_engine.get_role_config(role)
        clearance = role_config["clearance"] if role_config else "Unauthorized"

        if not session_context:
            session_context = {}

        return {
            "user_id": user_id,
            "role": role,
            "clearance": clearance,
            "session_context": {
                "session_id": session_context.get("session_id", f"sess-{uuid.uuid4().hex[:8]}"),
                "ip_address": session_context.get("ip_address", "0.0.0.0"),
                "request_timestamp": datetime.now(timezone.utc).isoformat(),
                "user_agent": session_context.get("user_agent", "Arbiter/2.0"),
            },
        }
