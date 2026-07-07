"""
Arbiter — Policy Engine (ABAC)
Evaluates access using Attribute-Based Access Control:
  clearance (role attribute) × sensitivity (resource attribute) → decision

No hardcoded resource lists. Adding a resource with a known sensitivity level
automatically inherits the correct access rules. Adding a role with a known
clearance level automatically resolves permissions against all resources.

Three-tier precedence:
  1. Access rules (clearance → allowed sensitivities)
  2. Exceptions (sensitivity-level overrides like own_only, deny)
  3. Prohibited combinations (specific clearance + resource blocks)
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
    ABAC policy engine. Resolves access by evaluating role clearance
    against resource sensitivity using rules from policies.json.
    """

    def __init__(self, tenant_id: str = "demo_university"):
        self.tenant_id = tenant_id
        self.policies = _load_json("policies.json")
        self.roles_config = _load_json("roles.json")
        self._institution = self.policies["institution_rules"]
        self._resources = self.policies["resources"]
        self._roles = self.roles_config["roles"]
        self._access_rules = {
            rule["clearance"]: rule
            for rule in self._institution.get("access_rules", [])
        }

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
        Evaluate ABAC policies for a role + user.

        Resolution order for each resource:
          1. Look up role's clearance
          2. Find matching access rule for that clearance
          3. Check if resource sensitivity is in allowed_sensitivity
          4. Check exceptions for that sensitivity level
          5. Check prohibited_combinations for specific blocks
          6. Result: authorized (with scope) or denied (with reason)
        """
        role_cfg = self._roles.get(role)
        if not role_cfg:
            return PolicyDecision(
                authorized_resources=[],
                denied_resources=list(self._resources.keys()),
                mask_fields=self._institution.get("always_mask", []),
                denial_reasons=[{"reason": f"Unknown role: {role}"}],
                decision="DENY",
                explanation=f"Role '{role}' is not recognized. All access denied.",
            )

        clearance = role_cfg.get("clearance", "Unknown")
        access_rule = self._access_rules.get(clearance)

        if not access_rule:
            return PolicyDecision(
                authorized_resources=[],
                denied_resources=list(self._resources.keys()),
                mask_fields=self._institution.get("always_mask", []),
                denial_reasons=[{"reason": f"No access rule for clearance: {clearance}"}],
                decision="DENY",
                explanation=f"Clearance '{clearance}' has no matching access rule. All access denied.",
            )

        allowed_sensitivity = set(access_rule.get("allowed_sensitivity", []))
        exceptions = access_rule.get("exceptions", {})
        prohibited = self._institution.get("prohibited_combinations", [])

        authorized = []
        denied = []
        denial_reasons = []
        is_scoped = False

        for resource_id, resource_meta in self._resources.items():
            sensitivity = resource_meta.get("sensitivity", "Restricted")

            # Step 1: Check prohibited combinations (highest precedence)
            is_prohibited = False
            for rule in prohibited:
                if (rule.get("clearance") == clearance
                        and rule.get("sensitivity") == sensitivity
                        and rule.get("resource_type") == resource_id):
                    denied.append(resource_id)
                    denial_reasons.append({
                        "resource": resource_id,
                        "reason": rule.get("reason", "Prohibited by policy"),
                    })
                    is_prohibited = True
                    break

            if is_prohibited:
                continue

            # Step 2: Check exceptions for this sensitivity level
            if sensitivity in exceptions:
                exception_action = exceptions[sensitivity]

                if exception_action == "deny":
                    denied.append(resource_id)
                    denial_reasons.append({
                        "resource": resource_id,
                        "reason": f"Denied by exception: {clearance} cannot access {sensitivity} resources",
                    })
                    continue
                elif exception_action == "own_only":
                    # Authorized but scoped — filter_data handles the actual scoping
                    authorized.append(resource_id)
                    is_scoped = True
                    continue
                elif exception_action == "deny_standing":
                    # Specific exception: deny this resource type even though sensitivity is allowed
                    if resource_id == "academic_standing":
                        denied.append(resource_id)
                        denial_reasons.append({
                            "resource": resource_id,
                            "reason": f"Standing denied for {clearance} clearance",
                        })
                        continue
                    else:
                        # Other resources with this sensitivity are still allowed
                        authorized.append(resource_id)
                        continue

            # Step 3: Check if sensitivity is in allowed list
            if sensitivity in allowed_sensitivity:
                authorized.append(resource_id)
            else:
                denied.append(resource_id)
                denial_reasons.append({
                    "resource": resource_id,
                    "reason": f"{clearance} clearance cannot access {sensitivity} resources",
                })

        # Mask fields: institution-level + role-level overrides
        mask_fields = list(self._institution.get("always_mask", []))
        mask_fields.extend(role_cfg.get("mask_overrides", []))
        mask_fields = list(set(mask_fields))

        # Determine overall decision
        if not authorized:
            decision = "DENY"
        elif denied or denial_reasons or is_scoped:
            decision = "ALLOW_PARTIAL"
        else:
            decision = "ALLOW_FULL"

        explanation = self._build_explanation(
            role, clearance, authorized, denied, mask_fields, decision, is_scoped
        )

        return PolicyDecision(
            authorized_resources=authorized,
            denied_resources=denied,
            mask_fields=mask_fields,
            denial_reasons=denial_reasons,
            decision=decision,
            explanation=explanation,
        )

    def _build_explanation(
        self, role: str, clearance: str,
        authorized: list[str], denied: list[str],
        mask_fields: list[str], decision: str, is_scoped: bool,
    ) -> str:
        parts = [f"{role} (clearance: {clearance}) requested data."]

        if decision == "ALLOW_FULL":
            parts.append(f"Full access granted to: {', '.join(authorized)}.")
        elif decision == "ALLOW_PARTIAL":
            parts.append(f"Granted: {', '.join(authorized)}.")
            if denied:
                parts.append(f"Denied: {', '.join(denied)}.")
            if is_scoped:
                parts.append("Some resources scoped to own records only.")
        else:
            parts.append("All access denied.")

        if mask_fields:
            parts.append(f"Masked: {', '.join(mask_fields)} (institution policy).")

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