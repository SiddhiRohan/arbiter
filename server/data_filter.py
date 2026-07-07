"""
Arbiter — Data Filter (Generic, Scalable)
Takes raw tenant data + a PolicyDecision, returns only what the user is allowed to see.

Fully generic — no resource names hardcoded in the filter loop.
Adding a new resource requires zero changes to this file IF:
  - The resource uses a standard scope type (own_only, all, none)
  - The scope_key is defined in policies.json

For new scope types (e.g. "department_only"), register a resolver below.
"""

import copy
from typing import Optional

from policy_engine import PolicyDecision


# ================================================================
# Scope Resolver Registry
#
# Each resolver takes (raw_data, user_id, resource_name, resource_config)
# and returns either:
#   None              → pass all records (no filtering)
#   (field, set)      → keep records where record[field] is in the set
# ================================================================

_SCOPE_RESOLVERS = {}


def _register(name):
    """Decorator to register a scope resolver by name."""
    def decorator(fn):
        _SCOPE_RESOLVERS[name] = fn
        return fn
    return decorator


@_register("all")
def _scope_all(raw_data, user_id, resource_name, resource_config):
    return None


@_register("none")
def _scope_none(raw_data, user_id, resource_name, resource_config):
    return ("__deny__", set())


@_register("own_only")
def _scope_own(raw_data, user_id, resource_name, resource_config):
    field = resource_config.get("scope_key", "person_id")
    return (field, {user_id})


@_register("own_classes")
def _scope_own_classes(raw_data, user_id, resource_name, resource_config):
    class_ids = {
        c["class_id"]
        for c in raw_data.get("classes", [])
        if c.get("teacher_id") == user_id
    }
    filter_field = "class_id" if "class_id" in _guess_fields(raw_data, resource_name) else resource_config.get("scope_key", "class_id")
    return (filter_field, class_ids)


@_register("advisees_only")
def _scope_advisees(raw_data, user_id, resource_name, resource_config):
    advisee_ids = {
        a["student_id"]
        for a in raw_data.get("advisor_assignments", [])
        if a.get("advisor_id") == user_id
    }
    field = resource_config.get("scope_key", "student_id")
    return (field, advisee_ids)


@_register("assigned_courses_only")
def _scope_assigned_courses(raw_data, user_id, resource_name, resource_config):
    class_ids = {
        t["class_id"]
        for t in raw_data.get("ta_assignments", [])
        if t.get("student_id") == user_id
    }
    filter_field = "class_id" if "class_id" in _guess_fields(raw_data, resource_name) else resource_config.get("scope_key", "class_id")
    return (filter_field, class_ids)


def _guess_fields(raw_data: dict, resource_name: str) -> set[str]:
    """Get field names from the first record of a resource."""
    records = raw_data.get(resource_name, [])
    if records and isinstance(records, list) and isinstance(records[0], dict):
        return set(records[0].keys())
    return set()


# ================================================================
# Resource-specific view limiters
#
# Optional: restrict which fields a role can see for a resource.
# If a resource isn't here, all fields pass through.
# Keyed by (resource_name, clearance_level).
# ================================================================

_VIEW_LIMITERS = {
    ("classes", "Self-Scoped"): [
        "class_id", "name", "teacher_name", "schedule",
        "room", "credits", "enrolled_students",
    ],
}


# ================================================================
# Main filter — fully generic
# ================================================================

def filter_data(
    raw_data: dict,
    policy: PolicyDecision,
    role: str,
    user_id: str,
    role_config: dict,
    channels_blocked: Optional[list[dict]] = None,
    resource_configs: Optional[dict] = None,
) -> dict:
    """
    Apply policy-based filtering to raw tenant data.
    Iterates over all resources in the data — no hardcoded resource names.

    Args:
        raw_data: full tenant dataset
        policy: evaluated PolicyDecision from the policy engine
        role: user's role name
        user_id: user's person_id
        role_config: role configuration from roles.json
        channels_blocked: inference channels to enforce
        resource_configs: resource metadata from policies.json (sensitivity, scope_key, etc.)
    """
    filtered = {}
    withheld_fields = _get_withheld_fields(channels_blocked)
    clearance = role_config.get("clearance", "Self-Scoped")
    resource_configs = resource_configs or {}

    # Identify which keys in raw_data are actual resources (skip metadata)
    metadata_keys = {"tenant_id", "data_source", "last_updated"}
    resource_names = [k for k in raw_data.keys() if k not in metadata_keys]

    for resource_name in resource_names:
        records = raw_data.get(resource_name, [])
        res_config = resource_configs.get(resource_name, {})

        # Step 1: Authorization check
        if resource_name not in policy.authorized_resources:
            filtered[resource_name] = f"[ACCESS DENIED — Your role cannot access {resource_name}.]"
            continue

        # Step 2: Deep copy to avoid mutating source
        if isinstance(records, list):
            records = copy.deepcopy(records)
        else:
            filtered[resource_name] = records
            continue

        # Step 3: Determine scope and filter records
        scope_type = _resolve_scope_type(resource_name, role_config)
        resolver = _SCOPE_RESOLVERS.get(scope_type)

        if resolver is None:
            # Unknown scope type — deny by default (fail-closed)
            filtered[resource_name] = f"[ACCESS DENIED — Unknown scope: {scope_type}]"
            continue

        scope_result = resolver(raw_data, user_id, resource_name, res_config)

        if scope_result is not None:
            filter_field, allowed_values = scope_result
            if filter_field == "__deny__":
                filtered[resource_name] = f"[ACCESS DENIED — Your role cannot access {resource_name}.]"
                continue
            records = [r for r in records if r.get(filter_field) in allowed_values]
            if scope_type != "all":
                filtered[f"{resource_name}_note"] = _scope_note(scope_type, role, resource_name)

        # Step 4: Apply field masks (SSN, etc.)
        for record in records:
            _apply_masks(record, policy.mask_fields)

        # Step 5: Apply inference channel withholding
        resource_withheld = [w for w in withheld_fields if w.startswith(f"{resource_name}.")]
        for withheld in resource_withheld:
            field_name = withheld.split(".", 1)[1]
            for record in records:
                record.pop(field_name, None)
            channel_info = _find_channel(channels_blocked, withheld)
            filtered[f"{resource_name}_inference_note"] = (
                f"{field_name} withheld — inference channel {channel_info} detected."
            )

        # Step 6: Apply view limiter (restrict visible fields for certain roles)
        limiter_key = (resource_name, clearance)
        if limiter_key in _VIEW_LIMITERS:
            allowed_fields = _VIEW_LIMITERS[limiter_key]
            records = [
                {k: v for k, v in record.items() if k in allowed_fields}
                for record in records
            ]

        filtered[resource_name] = records

    return filtered


# ================================================================
# Helpers
# ================================================================

def _resolve_scope_type(resource_name: str, role_config: dict) -> str:
    """
    Determine the scope type for a resource from role config.
    Checks for {resource}_scope, then falls back based on clearance.
    """
    # Direct scope config: e.g. "financial_scope": "own_only"
    # Try exact match first, then prefix match
    for key in [f"{resource_name}_scope", f"{'_'.join(resource_name.split('_')[:1])}_scope"]:
        scope = role_config.get(key)
        if scope:
            return scope

    # Map common resource names to their scope keys
    scope_key_map = {
        "financial_information": "financial_scope",
        "academic_standing": "standing_scope",
        "grades": "grades_scope",
    }
    mapped_key = scope_key_map.get(resource_name)
    if mapped_key:
        scope = role_config.get(mapped_key)
        if scope:
            return scope

    # Fallback: Full-Access gets all, everyone else gets all for authorized resources
    clearance = role_config.get("clearance", "Self-Scoped")
    if clearance == "Full-Access":
        return "all"

    return "all"


def _get_withheld_fields(channels_blocked: Optional[list[dict]]) -> set[str]:
    """Extract the set of fields to withhold from blocked inference channels."""
    if not channels_blocked:
        return set()
    return {ch["withheld_field"] for ch in channels_blocked}


def _find_channel(channels_blocked: Optional[list[dict]], withheld_field: str) -> str:
    """Find the channel ID that triggered a withheld field."""
    if not channels_blocked:
        return "unknown"
    for ch in channels_blocked:
        if ch.get("withheld_field") == withheld_field:
            return f"{ch.get('channel_id', '?')} ({ch.get('name', '?')})"
    return "unknown"


def _apply_masks(record: dict, mask_fields: list[str]) -> None:
    """Replace masked field values with redaction markers in-place."""
    for field in mask_fields:
        if field in record:
            record[field] = "***-**-****" if field == "ssn" else "[MASKED]"


def _scope_note(scope_type: str, role: str, resource_name: str) -> str:
    """Human-readable note explaining why data is scoped."""
    notes = {
        "own_only": f"Filtered to your own records only.",
        "own_classes": f"Filtered to classes you teach.",
        "advisees_only": f"Filtered to your advisees only.",
        "assigned_courses_only": f"Filtered to your assigned course(s) only.",
    }
    return notes.get(scope_type, f"{resource_name} scoped to authorized records.")


# ================================================================
# Text renderer — generic
# ================================================================

def to_text(filtered_data: dict) -> str:
    """
    Convert filtered data dict into a readable text block for the LLM context.
    Fully generic — renders any resource without hardcoded field names.
    """
    sections = []

    for resource_name, data in filtered_data.items():
        # Skip metadata notes
        if resource_name.endswith("_note") or resource_name.endswith("_inference_note"):
            continue

        section = [f"\n=== {resource_name.upper().replace('_', ' ')} ==="]

        # Access denied string
        if isinstance(data, str):
            section.append(f"  {data}")
            sections.append("\n".join(section))
            continue

        # Scope note
        note = filtered_data.get(f"{resource_name}_note")
        if note:
            section.append(f"  Note: {note}")

        # Inference note
        inf_note = filtered_data.get(f"{resource_name}_inference_note")
        if inf_note:
            section.append(f"  [INFERENCE CONTROL] {inf_note}")

        # Render records generically
        if isinstance(data, list):
            for record in data:
                if isinstance(record, dict):
                    section.append("  " + _render_record(record))
                else:
                    section.append(f"  {record}")
        else:
            section.append(f"  {data}")

        sections.append("\n".join(section))

    return "\n".join(sections)


def _render_record(record: dict) -> str:
    """
    Render a single record as a readable line.
    Uses heuristics to format nicely without knowing the schema.
    """
    parts = []

    # Lead with identifiers if present
    id_fields = ["person_id", "student_id", "dept_id", "class_id",
                 "record_id", "hold_id", "ta_id", "advisor_id"]
    lead_id = None
    for idf in id_fields:
        if idf in record:
            lead_id = f"{record[idf]}"
            break

    # Lead with name if present
    name = record.get("name")
    if name and lead_id:
        parts.append(f"{name} ({lead_id})")
    elif lead_id:
        parts.append(lead_id)
    elif name:
        parts.append(name)

    # Render remaining fields
    skip = set(id_fields) | {"name"}
    for key, value in record.items():
        if key in skip:
            continue
        if isinstance(value, list):
            value = f"[{', '.join(str(v) for v in value)}]"
        elif isinstance(value, float):
            if value < 1 and value > 0:
                value = f"{value * 100:.0f}%"
            else:
                value = f"{value:,.2f}"
        elif isinstance(value, int) and value > 999:
            value = f"${value:,}"

        display_key = key.replace("_", " ").title()
        parts.append(f"{display_key}: {value}")

    return " | ".join(parts)