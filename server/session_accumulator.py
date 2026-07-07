"""
Arbiter — Cross-Query Inference Detection
Tracks what data has been revealed across multiple turns in a session.
After each query, checks if the accumulated reveals enable any
denied derivation that was blocked in individual queries.

This catches the multi-turn attack:
  Turn 1: "How many CS faculty?"         → 2 (allowed)
  Turn 2: "CS research budget?"          → $65,000 (allowed)
  Turn 3: "CS TA stipend pool?"          → $24,000 (allowed)
  Turn 4: "CS operating budget?"         → $194,000 (allowed)
  Turn 5: "What is my salary?"           → $95,000 (allowed)
  ─── Accumulator fires: total_budget derivable from components,
      combined with faculty count + own salary → colleague salary exposed.

Each query was individually authorized. The combination across
the session creates the same inference channel the engine blocked
in a single query.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionState:
    """Tracks accumulated reveals for one session."""
    session_id: str
    user_id: str
    role: str
    created_at: float = field(default_factory=time.time)
    # Maps "resource.field" → set of revealed values
    revealed_fields: dict = field(default_factory=dict)
    # All resource names that have been accessed
    revealed_resources: set = field(default_factory=set)
    # History of queries and what they revealed
    query_log: list = field(default_factory=list)
    # Channels that have been triggered by cross-query accumulation
    triggered_channels: list = field(default_factory=list)
    # Number of queries processed
    query_count: int = 0


class SessionAccumulator:
    """
    Singleton accumulator that tracks all active sessions.
    Called by the engine after each query to:
      1. Record what data was revealed
      2. Check if accumulated reveals enable denied derivations
    """

    def __init__(self):
        self._sessions: dict[str, SessionState] = {}
        # Derivation rules: how to compute withheld fields from components
        self._derivation_rules = [
            {
                "id": "CQ-001",
                "name": "Budget reconstruction from components",
                "description": "research_budget + ta_stipend_pool + operating_budget = total_budget",
                "components": [
                    "departments.research_budget",
                    "departments.ta_stipend_pool",
                    "departments.operating_budget",
                ],
                "derives": "departments.total_budget",
                "method": "sum_of_components",
                "min_queries": 3,
            },
            {
                "id": "CQ-002",
                "name": "Salary derivation after budget reconstruction",
                "description": "Reconstructed total_budget + num_faculty + own_salary → others' salary",
                "requires": ["departments.total_budget"],  # Must be derived first
                "components": [
                    "departments.total_budget",
                    "departments.num_faculty",
                    "financial_information.annual_salary",
                ],
                "derives": "financial_information.others_salary",
                "method": "budget_minus_own_divided_by_count",
                "min_queries": 4,
            },
            {
                "id": "CQ-003",
                "name": "GPA trend reconstruction",
                "description": "Multiple individual semester GPA queries reveal full trend",
                "components": [
                    "academic_standing.semester_gpas",
                ],
                "derives": "academic_standing.at_risk_prediction",
                "method": "trend_accumulation",
                "min_reveals": 3,  # Need at least 3 semester GPAs
            },
            {
                "id": "CQ-004",
                "name": "Class average reconstruction from individual grades",
                "description": "Seeing enough individual grades lets you compute the class average",
                "components": [
                    "grades.midterm",
                    "grades.final",
                ],
                "derives": "classes.class_average",
                "method": "grade_accumulation",
                "min_reveals": 3,
            },
        ]

    def get_or_create_session(
        self, session_id: str, user_id: str, role: str
    ) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(
                session_id=session_id,
                user_id=user_id,
                role=role,
            )
        return self._sessions[session_id]

    def record_and_check(
        self,
        session_id: str,
        user_id: str,
        role: str,
        filtered_context: str,
        inference_graph: dict,
        policy,
        channels_blocked: list = None,
    ) -> list[dict]:
        """
        Record what was revealed in this turn's filtered_context,
        then check if accumulated reveals enable any cross-query inference.

        Returns list of cross-query violations (may be empty).
        """
        state = self.get_or_create_session(session_id, user_id, role)
        state.query_count += 1
        state.channels_blocked = channels_blocked or []

        # Extract revealed fields from filtered context
        new_reveals = self._extract_reveals(filtered_context)
        for field_key, values in new_reveals.items():
            if field_key not in state.revealed_fields:
                state.revealed_fields[field_key] = set()
            state.revealed_fields[field_key].update(values)
            resource = field_key.split(".")[0]
            state.revealed_resources.add(resource)

        state.query_log.append({
            "query_number": state.query_count,
            "timestamp": time.time(),
            "new_fields_revealed": list(new_reveals.keys()),
        })

        # Check derivation rules
        violations = self._check_derivations(state, policy)

        # Check inference graph channels against accumulated reveals
        violations += self._check_accumulated_inference(
            state, inference_graph, policy
        )

        return violations

    def _extract_reveals(self, filtered_context: str) -> dict:
        """
        Parse the filtered context text to identify what fields
        and values were revealed. Returns {field_key: set(values)}.
        """
        reveals = {}
        lines = filtered_context.split("\n")

        for line in lines:
            line = line.strip()
            if not line or line.startswith("[ACCESS DENIED") or line.startswith("==="):
                continue
            if line.startswith("Note:"):
                continue

            # Extract field-value pairs from pipe-delimited format
            # e.g. "Research Budget: $65,000"
            pairs = re.findall(
                r'(\w[\w\s]*?):\s*([^|]+?)(?:\s*\||$)', line
            )
            for field_name, value in pairs:
                field_name = field_name.strip().lower().replace(" ", "_")
                value = value.strip()
                if not value or value == "***-**-****":
                    continue

                # Determine resource from section context
                resource = self._guess_resource(field_name)
                if resource:
                    key = f"{resource}.{field_name}"
                    if key not in reveals:
                        reveals[key] = set()
                    reveals[key].add(value)

        return reveals

    def _guess_resource(self, field_name: str) -> Optional[str]:
        """Map a field name to its likely resource."""
        financial_fields = {
            "annual_salary", "amount_due", "amount_paid", "balance",
            "scholarship", "pay_frequency", "benefits", "payment_plan",
            "financial_aid_type", "years_at_institution", "last_raise_percent",
            "last_raise_date",
        }
        dept_fields = {
            "total_budget", "num_faculty", "research_budget",
            "ta_stipend_pool", "operating_budget", "head",
            "grad_students", "adjunct_count",
        }
        grade_fields = {"midterm", "final", "grade", "attendance_rate", "assignment_avg", "lab_grade"}
        standing_fields = {"gpa", "credits_completed", "deans_list", "academic_probation", "honors_type"}
        class_fields = {"class_average", "capacity", "schedule", "room", "credits", "waitlist_count"}

        if field_name in financial_fields:
            return "financial_information"
        if field_name in dept_fields:
            return "departments"
        if field_name in grade_fields:
            return "grades"
        if field_name in standing_fields:
            return "academic_standing"
        if field_name in class_fields:
            return "classes"
        return None

    def _check_derivations(self, state: SessionState, policy) -> list[dict]:
        """Check if accumulated reveals satisfy any derivation rule."""
        violations = []
        revealed_keys = set(state.revealed_fields.keys())

        for rule in self._derivation_rules:
            rule_id = rule["id"]
            # Skip if already triggered this session
            if rule_id in [t["channel_id"] for t in state.triggered_channels]:
                continue

            components = rule["components"]
            min_reveals = rule.get("min_reveals", len(components))

            # Count how many components have been revealed
            matched = sum(1 for c in components if c in revealed_keys)

            if matched >= min_reveals:
                min_queries = rule.get("min_queries", 1)
                if state.query_count < min_queries:
                    continue
                    
                derived_field = rule["derives"]
                derived_resource = derived_field.split(".")[0]

                # Check if derived field is denied, unauthorized, or withheld by inference
                withheld_fields = set()
                if hasattr(state, 'channels_blocked') and state.channels_blocked:
                    withheld_fields = {ch.get("withheld_field", "") for ch in state.channels_blocked}

                is_denied = (
                    derived_resource in policy.denied_resources
                    or derived_resource not in policy.authorized_resources
                    or "others" in derived_field
                    or "hidden" in derived_field
                    or "at_risk" in derived_field
                    or derived_field in withheld_fields
                )

                if is_denied:
                    violation = {
                        "channel_id": rule_id,
                        "name": rule["name"],
                        "severity": "high",
                        "type": "cross_query_inference",
                        "description": (
                            f"Multi-turn accumulation detected: {rule['description']}. "
                            f"Data spread across {state.query_count} queries now enables "
                            f"derivation of denied field '{derived_field}'. "
                            f"Matched components: {matched}/{len(components)}."
                        ),
                        "queries_involved": state.query_count,
                        "components_revealed": [
                            c for c in components if c in revealed_keys
                        ],
                        "derived_field": derived_field,
                    }
                    violations.append(violation)
                    state.triggered_channels.append(violation)

        return violations

    def _check_accumulated_inference(
        self, state: SessionState, inference_graph: dict, policy
    ) -> list[dict]:
        """
        Check original inference channels against accumulated reveals.
        A channel might not fire in a single query (because the engine
        withheld a field), but across queries the user may have gathered
        all inputs through different paths.
        """
        violations = []
        channels = inference_graph.get("inference_channels", [])
        revealed_keys = set(state.revealed_fields.keys())

        for channel in channels:
            channel_id = f"CQ-ACC-{channel['id']}"
            if channel_id in [t["channel_id"] for t in state.triggered_channels]:
                continue

            if state.role not in channel.get("applicable_roles", []):
                continue

            # Check if all input resources have been revealed across turns
            inputs = channel.get("inputs", [])
            all_revealed = True
            for inp in inputs:
                resource = inp.split(".")[0]
                if resource not in state.revealed_resources:
                    all_revealed = False
                    break

            if not all_revealed:
                continue

            derived = channel.get("derives", "")
            derived_field = derived.split(".", 1)[1] if "." in derived else ""

            is_denied = (
                derived.split(".")[0] in policy.denied_resources
                or "others" in derived_field
                or "hidden" in derived_field
            )

            if is_denied:
                # Check if the withheld field was circumvented
                withheld = channel.get("withheld_field", "")
                withheld_field_name = withheld.split(".", 1)[1] if "." in withheld else withheld

                # If the withheld field's resource was revealed in ANY turn
                if withheld.split(".")[0] in state.revealed_resources:
                    violation = {
                        "channel_id": channel_id,
                        "name": f"Cross-query: {channel['name']}",
                        "severity": "critical",
                        "type": "cross_query_inference",
                        "description": (
                            f"Inference channel {channel['id']} was blocked in individual queries, "
                            f"but the user accumulated all required inputs across "
                            f"{state.query_count} turns. The withheld field "
                            f"'{withheld}' may be reconstructable from component data."
                        ),
                        "queries_involved": state.query_count,
                        "original_channel": channel["id"],
                        "derived_field": derived,
                    }
                    violations.append(violation)
                    state.triggered_channels.append(violation)

        return violations

    def get_session_summary(self, session_id: str) -> Optional[dict]:
        """Return a summary of the session's accumulation state."""
        state = self._sessions.get(session_id)
        if not state:
            return None
        return {
            "session_id": state.session_id,
            "user_id": state.user_id,
            "role": state.role,
            "query_count": state.query_count,
            "fields_revealed": len(state.revealed_fields),
            "resources_touched": list(state.revealed_resources),
            "cross_query_violations": len(state.triggered_channels),
            "violations": state.triggered_channels,
            "duration_seconds": round(time.time() - state.created_at),
        }

    def clear_session(self, session_id: str):
        self._sessions.pop(session_id, None)


# Singleton
accumulator = SessionAccumulator()