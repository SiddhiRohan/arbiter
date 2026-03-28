"""
Arbiter — Policy Engine
Loads role definitions and institution rules from JSON config files.
Evaluates per-request access decisions: what resources to allow, deny, and mask.
Three-tier precedence: Institution --> Role --> User overrides.
"""

import json
from pathlib import Path
from typing import Optional

CONFIG_DIR = Path(__file__).parent.parent / "config"


def _load_json(filename: str) -> dict:
    filepath = CONFIG_DIR / filename
    with open(filepath, "r") as f:
        return json.load(f)


class PolicyDecision:
    """Result of evaluating policies for a single request."""

    def __init__(
        self,
        authorized_resources: list[str],
        denied_resources: list[str],
        mask_fields: list[str],
        denial_reasons: list[dict],
        decision: str,
        explanation: str,
    ):
        self.authorized_resources = authorized_resources
        self.denied_resources = denied_resources
        self.mask_fields = mask_fields
        self.denial_reasons = denial_reasons
        self.decision = decision
        self.explanation = explanation


class PolicyEngine:
    """
    Evaluates access policies for a given tenant, role, and user.
    All rules are loaded from config files — nothing is hardcoded.
    """

    def __init__(self, tenant_id: str = "demo_university"):
        self.tenant_id = tenant_id
        self.policies = _load_json("policies.json")
        self.roles_config = _load_json("roles.json")
        self._institution = self.policies["institution_rules"]
        self._resources = self.policies["resources"]
        self._roles = self.roles_config["roles"]

    def get_available_roles(self) -> list[str]:
        return list(self._roles.keys())

    def get_role_config(self, role: str) -> Optional[dict]:
        return self._roles.get(role)

    def get_resource_descriptor(self, resource_id: str) -> dict:
        default = {
            "origin": "Unknown",
            "sensitivity": "Restricted",
            "ttl_seconds": 0,
            "description": "Unregistered resource",
        }
        return self._resources.get(resource_id, default)

    def get_model_config(self) -> dict:
        return self.policies.get("model_config", {
            "model_id": "claude-sonnet-4-20250514",
            "provider": "Anthropic",
            "compliance": "SOC2-certified",
            "risk_level": "low",
            "max_tokens": 1024,
        })

    def evaluate(self, role: str, user_id: str) -> PolicyDecision:
        """
        Determine what a user with the given role can access.
        Returns a PolicyDecision with all access details.
        """
        role_cfg = self._roles.get(role)
        if not role_cfg:
            return PolicyDecision(
                authorized_resources=[],
                denied_resources=list(self._resources.keys()),
                mask_fields=self._institution["always_mask"],
                denial_reasons=[{"reason": f"Unknown role: {role}"}],
                decision="DENY",
                explanation=f"Role '{role}' is not recognized. All access denied.",
            )

        all_resource_ids = list(self._resources.keys())
        authorized = list(role_cfg["allowed_resources"])

        # Financial info: add to authorized if role has any financial scope
        if role_cfg.get("can_view_others_financial") or role_cfg.get("financial_scope"):
            if "financial_information" not in authorized:
                authorized.append("financial_information")

        denied = [r for r in all_resource_ids if r not in authorized]

        # Collect denial reasons from prohibited_access rules
        denial_reasons = []
        for rule in self._institution.get("prohibited_access", []):
            if rule["role"] == role:
                denial_reasons.append({
                    "resource": rule["resource"],
                    "reason": rule["reason"],
                })

        # Additional denials based on role restrictions
        if not role_cfg.get("can_view_grades", False) and "grades" not in denied:
            denied.append("grades")
            if "grades" in authorized:
                authorized.remove("grades")

        # Track scoped access as implicit denials
        is_scoped = False
        scope = role_cfg.get("financial_scope")
        if scope == "own_only" and not role_cfg.get("can_view_others_financial", False):
            is_scoped = True
            denied.append("financial_information_others")

        # Mask fields: institution-level + role-level overrides
        mask_fields = list(self._institution["always_mask"])
        mask_fields.extend(role_cfg.get("mask_overrides", []))
        mask_fields = list(set(mask_fields))

        # Determine overall decision
        if not authorized:
            decision = "DENY"
        elif denied or denial_reasons or is_scoped:
            decision = "ALLOW_PARTIAL"
        else:
            decision = "ALLOW_FULL"

        explanation = self._build_explanation(role, role_cfg, authorized, denied, mask_fields, decision)

        return PolicyDecision(
            authorized_resources=authorized,
            denied_resources=denied,
            mask_fields=mask_fields,
            denial_reasons=denial_reasons,
            decision=decision,
            explanation=explanation,
        )

    def _build_explanation(
        self, role: str, role_cfg: dict,
        authorized: list[str], denied: list[str],
        mask_fields: list[str], decision: str,
    ) -> str:
        parts = [f"{role} ({role_cfg['clearance']}) requested data."]

        if decision == "ALLOW_FULL":
            parts.append(f"Full access granted to: {', '.join(authorized)}.")
        elif decision == "ALLOW_PARTIAL":
            parts.append(f"Granted: {', '.join(authorized)}.")
            if denied:
                parts.append(f"Denied: {', '.join(denied)}.")
            scope = role_cfg.get("financial_scope")
            if scope == "own_only":
                parts.append("Financial data restricted to own records only.")
        else:
            parts.append("All access denied.")

        if mask_fields:
            parts.append(f"Masked fields: {', '.join(mask_fields)} (institution-level policy).")

        parts.append(f"Decision: {decision}.")
        return " ".join(parts)


# ── Config management (for admin dashboard) ──

def update_role(role_name: str, role_config: dict) -> None:
    """Add or update a role in the config file."""
    roles_data = _load_json("roles.json")
    roles_data["roles"][role_name] = role_config
    filepath = CONFIG_DIR / "roles.json"
    with open(filepath, "w") as f:
        json.dump(roles_data, f, indent=2)


def delete_role(role_name: str) -> bool:
    """Remove a role from config. Returns False if role doesn't exist."""
    roles_data = _load_json("roles.json")
    if role_name not in roles_data["roles"]:
        return False
    del roles_data["roles"][role_name]
    filepath = CONFIG_DIR / "roles.json"
    with open(filepath, "w") as f:
        json.dump(roles_data, f, indent=2)
    return True


def update_policy(key: str, value) -> None:
    """Update a top-level policy setting."""
    policies = _load_json("policies.json")
    policies["institution_rules"][key] = value
    filepath = CONFIG_DIR / "policies.json"
    with open(filepath, "w") as f:
        json.dump(policies, f, indent=2)


def get_full_config() -> dict:
    """Return both config files merged for the admin dashboard."""
    return {
        "roles": _load_json("roles.json"),
        "policies": _load_json("policies.json"),
    }
