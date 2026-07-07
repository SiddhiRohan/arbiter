"""
Arbiter — Core Engine
Orchestrates the full bidirectional ICCP pipeline for every request:

INPUT GOVERNANCE (before LLM call):
  1. Build identity scope
  2. Evaluate ABAC policies (clearance vs resource sensitivity)
  3. Classify query intent (minimum necessary access)
  4. Detect inference channels from authorized data combinations
  5. Filter data based on policy + intent + inference control
  6. Check TTL freshness for each resource
  7. Build Context Packet (CCP v3.0)
  8. Log the input audit entry
  9. Return filtered context ready for the LLM

OUTPUT GOVERNANCE (after LLM responds):
  10. Scan LLM response for leakage, hallucination, mask breaches
  11. Sanitize response, log output audit entry, return to user

The API layer calls engine.process() for input governance,
then engine.govern_output() for output governance.
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from policy_engine import PolicyEngine, get_full_config
from data_filter import filter_data, to_text
from context_packet import build_packet
from audit_logger import log_entry
from output_scanner import scan_output
from query_intent import classify_query, scope_resources
from session_accumulator import accumulator

CONFIG_DIR = Path(__file__).parent.parent / "config"
DATA_DIR = Path(__file__).parent.parent / "data"


class ArbiterEngine:
    """
    Stateful engine that processes ICCP-governed requests.
    Tracks resource TTL timestamps across calls.
    Handles both input and output governance.
    """

    def __init__(self, tenant_id: str = "demo_university"):
        self.tenant_id = tenant_id
        self._ttl_timestamps: dict[str, float] = {}
        self._tenant_data: Optional[dict] = None
        self._inference_graph: Optional[dict] = None

    def _load_tenant_data(self) -> dict:
        """Load the data source for this tenant. Cached after first load."""
        if self._tenant_data is None:
            data_file = DATA_DIR / f"{self.tenant_id}.json"
            if not data_file.exists():
                raise FileNotFoundError(f"No data source found for tenant: {self.tenant_id}")
            with open(data_file, "r") as f:
                self._tenant_data = json.load(f)
        return self._tenant_data

    def _load_inference_graph(self) -> dict:
        """Load the causal inference graph config. Cached after first load."""
        if self._inference_graph is None:
            graph_file = CONFIG_DIR / "inference_graph.json"
            if graph_file.exists():
                with open(graph_file, "r") as f:
                    self._inference_graph = json.load(f)
            else:
                self._inference_graph = {"inference_channels": [], "detection_config": {}}
        return self._inference_graph

    def process(
        self,
        user_id: str,
        role: str,
        query: str,
        session_context: Optional[dict] = None,
    ) -> dict:
        """
        Run INPUT governance — everything before the LLM call.

        Returns dict with:
            - filtered_context: text for the LLM (only authorized, inference-safe data)
            - access_level: "full" | "partial" | "denied"
            - masked_fields: list of field names that were masked
            - denied_resources: list of resource IDs that were denied
            - inference_channels_blocked: list of channels detected and broken
            - query_intent: what the query actually needed
            - trace_id: unique identifier for this invocation
            - context_packet: full CCP v3.0 packet
            - _policy: internal PolicyDecision for output scanner
            - _raw_data: internal raw tenant data for output scanner
            - _filtered_context: internal filtered text for output scanner
        """
        trace_id = f"tr-{uuid.uuid4().hex[:8]}"

        # Step 1: Build identity scope
        identity = self._build_identity(user_id, role, session_context)

        # Step 2: Evaluate ABAC policies
        policy_engine = PolicyEngine(self.tenant_id)
        policy = policy_engine.evaluate(role, user_id)
        role_config = policy_engine.get_role_config(role) or {}
        model_config = policy_engine.get_model_config()
        resource_configs = policy_engine.policies.get("resources", {})

        # Step 3: Classify query intent — minimum necessary access
        intent = classify_query(query, available_resources=policy.authorized_resources)
        scoped_resources = scope_resources(intent, policy.authorized_resources)

        # If intent scoping returned specific resources, narrow the authorized set
        # Otherwise (ambiguous/broad), keep the full authorized set
        if intent.intent_category not in ("ambiguous", "broad", "general") and scoped_resources:
            effective_resources = scoped_resources
        else:
            effective_resources = policy.authorized_resources

        # Step 4: Detect inference channels
        inference_graph = self._load_inference_graph()
        channels_blocked = self._detect_inference_channels(
            inference_graph, role, policy
        )

        # Step 5: Filter data based on policy + intent + inference control
        tenant_data = self._load_tenant_data()
        filtered = filter_data(
            raw_data=tenant_data,
            policy=policy,
            role=role,
            user_id=user_id,
            role_config=role_config,
            channels_blocked=channels_blocked,
            resource_configs=resource_configs,
        )

        # Apply query intent scoping — remove resources the query doesn't need
        if effective_resources != policy.authorized_resources:
            for resource_name in list(filtered.keys()):
                # Keep notes and metadata
                if resource_name.endswith("_note") or resource_name.endswith("_inference_note"):
                    continue
                if resource_name not in effective_resources:
                    # Don't replace with ACCESS DENIED — this is intent scoping, not policy denial
                    filtered.pop(resource_name, None)
                    # Also remove associated notes
                    filtered.pop(f"{resource_name}_note", None)
                    filtered.pop(f"{resource_name}_inference_note", None)

        filtered_context = to_text(filtered)

        # Step 6: Check TTL freshness for authorized resources
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

        # Determine access level
        if not policy.authorized_resources:
            access_level = "denied"
        elif policy.denied_resources or channels_blocked:
            access_level = "partial"
        else:
            access_level = "full"

        # Step 7: Build Context Packet (CCP v3.0)
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
            inference_channels_blocked=channels_blocked,
        )

        # Step 8: Log the input audit entry
        log_entry(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            identity_scope=identity,
            session_context=identity.get("session_context", {}),
            model_id=model_config.get("model_id", "unknown"),
            resources_accessed=effective_resources,
            resources_denied=policy.denied_resources,
            fields_masked=policy.mask_fields,
            policy_decision=policy.decision,
            explanation=policy.explanation,
            ttl_status=ttl_status,
            inference_channels_blocked=channels_blocked,
        )
        # Step 9: Cross-query inference detection
        accumulator_key = f"{user_id}:{role}"
        cross_query_violations = accumulator.record_and_check(
            session_id=accumulator_key,
            user_id=user_id,
            role=role,
            filtered_context=filtered_context,
            inference_graph=inference_graph,
            policy=policy,
            channels_blocked=channels_blocked,
        )

        if cross_query_violations:
            log_entry(
                trace_id=trace_id,
                tenant_id=self.tenant_id,
                identity_scope=identity,
                session_context=identity.get("session_context", {}),
                model_id="cross_query_detection",
                resources_accessed=[],
                resources_denied=[],
                fields_masked=[],
                policy_decision="CROSS_QUERY_INFERENCE",
                explanation=f"Cross-query inference: {len(cross_query_violations)} violation(s) across {cross_query_violations[0].get('queries_involved', 0)} turns",
                ttl_status={},
                inference_channels_blocked=cross_query_violations,
            )

        return {
            "filtered_context": filtered_context,
            "access_level": access_level,
            "masked_fields": policy.mask_fields,
            "denied_resources": policy.denied_resources,
            "inference_channels_blocked": channels_blocked,
            "cross_query_violations": cross_query_violations,
            "query_intent": {
                "category": intent.intent_category,
                "required_resources": intent.required_resources,
                "effective_resources": effective_resources,
                "confidence": intent.confidence,
                "explanation": intent.explanation,
            },
            "trace_id": trace_id,
            "context_packet": packet,
            # Internal state for output scanner — not sent to client
            "_policy": policy,
            "_raw_data": tenant_data,
            "_filtered_context": filtered_context,
        }

    def govern_output(
        self,
        trace_id: str,
        llm_response: str,
        policy,
        raw_data: dict,
        filtered_context: str,
    ) -> dict:
        """
        Run OUTPUT governance — scan LLM response for violations.
        Called by main.py after the LLM responds.

        Returns dict with:
            - sanitized_response: the cleaned response (violations redacted)
            - violations: list of violations found
            - decision: "clean" | "redacted" | "blocked"
        """
        scan_result = scan_output(
            llm_response=llm_response,
            policy=policy,
            raw_data=raw_data,
            filtered_context=filtered_context,
        )

        # Log output governance event
        log_entry(
            trace_id=trace_id,
            tenant_id=self.tenant_id,
            identity_scope={"user_id": "system", "role": "output_scanner", "clearance": "internal"},
            session_context={},
            model_id="output_governance",
            resources_accessed=[],
            resources_denied=[],
            fields_masked=[],
            policy_decision=f"OUTPUT_{scan_result['decision'].upper()}",
            explanation=f"Output scan: {len(scan_result['violations'])} violation(s) detected",
            ttl_status={},
            output_violations=scan_result["violations"],
            output_decision=scan_result["decision"],
        )

        return scan_result

    def _detect_inference_channels(
        self, inference_graph: dict, role: str, policy
    ) -> list[dict]:
        """
        Check if the authorized data for this role enables any
        causal inference channels. Supports both:
          - Static channels (inference_channels[] in config)
          - Template channels (channel_templates[] in config) — scalable
        """
        blocked = []
        config = inference_graph.get("detection_config", {})

        if not config.get("enable_runtime_detection", True):
            return blocked

        # ── Static channels (backward compatible) ──
        for channel in inference_graph.get("inference_channels", []):
            if role not in channel.get("applicable_roles", []):
                continue

            inputs = channel.get("inputs", [])
            all_inputs_authorized = True
            for input_field in inputs:
                resource = input_field.split(".")[0]
                if resource not in policy.authorized_resources:
                    all_inputs_authorized = False
                    break

            derived = channel.get("derives", "")
            derived_resource = derived.split(".")[0]
            derived_field = derived.split(".", 1)[1] if "." in derived else ""

            derives_denied = (
                derived_resource in policy.denied_resources
                or derived_resource not in policy.authorized_resources
            )
            if not derives_denied and ("others" in derived_field or "hidden" in derived_field):
                derives_denied = True

            if all_inputs_authorized and derives_denied:
                blocked.append({
                    "channel_id": channel["id"],
                    "name": channel["name"],
                    "severity": channel["severity"],
                    "withheld_field": channel["withheld_field"],
                    "method": channel["method"],
                    "compliance": channel["compliance"],
                })

        # ── Template channels (scalable) ──
        if not config.get("template_matching", False):
            return blocked

        tenant_data = self._load_tenant_data()
        role_config = PolicyEngine(self.tenant_id).get_role_config(role) or {}
        metadata_keys = {"tenant_id", "data_source", "last_updated"}

        for template in inference_graph.get("channel_templates", []):
            match = template.get("match", {})
            applicable_scopes = template.get("applicable_scopes", [])

            # Check if any of the role's scopes match this template
            role_scopes = [v for k, v in role_config.items() if k.endswith("_scope")]
            if applicable_scopes and not any(s in applicable_scopes for s in role_scopes):
                continue
            # Check applicable roles
            applicable_roles = template.get("applicable_roles", [])
            if applicable_roles and role not in applicable_roles:
                continue

            # Match template against each resource in the data
            for resource_name, records in tenant_data.items():
                if resource_name in metadata_keys or not isinstance(records, list) or not records:
                    continue
                if resource_name not in policy.authorized_resources:
                    continue

                sample = records[0] if isinstance(records[0], dict) else {}
                matched_fields = []

                # Check if the resource has all the fields the template expects
                for key, value in match.items():
                    if key.endswith("_field"):
                        field_name = value
                        if field_name in sample:
                            matched_fields.append(field_name)
                        else:
                            break
                else:
                    # All fields matched — this template applies to this resource
                    if not matched_fields:
                        continue

                    withheld_pattern = template.get("withheld_field_pattern", "")
                    withheld_field = withheld_pattern.replace("{resource}", resource_name)

                    # Deduplicate — don't block same field twice
                    already_blocked = {b["withheld_field"] for b in blocked}
                    if withheld_field in already_blocked:
                        continue

                    blocked.append({
                        "channel_id": f"{template['template_id']}:{resource_name}",
                        "name": f"{template['name']} ({resource_name})",
                        "severity": template["severity"],
                        "withheld_field": withheld_field,
                        "method": template["method"],
                        "compliance": template["compliance"],
                    })

        return blocked
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
                "user_agent": session_context.get("user_agent", "Arbiter/3.0"),
            },
        }