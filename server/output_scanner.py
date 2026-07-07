"""
Arbiter — Output Governance Scanner
Scans LLM responses BEFORE they reach the user.

Catches three violation types:
  1. LEAKAGE   — response contains denied data values (salary figures, grades, etc.)
  2. MASK_BREACH — response contains patterns matching masked fields (SSN format)
  3. HALLUCINATION — response contains data-like claims not present in filtered context

Uses the same PolicyDecision that governed the input — same policy, both directions.
Fully generic — no resource names hardcoded. Scans against raw data values.
"""

import re
from typing import Optional


# SSN pattern: 3-2-4 digits
_SSN_PATTERN = re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b")

# Currency pattern: dollar amounts
_CURRENCY_PATTERN = re.compile(r"\$[\d,]+(?:\.\d{2})?")

# Percentage pattern
_PERCENTAGE_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d+)?%")

# Fields that are too generic to flag as leakage
_SKIP_FIELDS = {
    "status", "type", "role", "department", "shift", "certification",
    "employment_status", "payment_plan", "pay_frequency", "enrollment_date",
    "date_of_birth", "date_diagnosed", "start_date", "date",
}


def scan_output(
    llm_response: str,
    policy,
    raw_data: dict,
    filtered_context: str,
) -> dict:
    violations = []
    sanitized = llm_response

    # ── Check 1: Mask breaches (SSN patterns in output) ──
    ssn_violations, sanitized = _check_mask_breaches(sanitized, raw_data)
    violations.extend(ssn_violations)

    # ── Check 2: Leakage (denied data values appearing in output) ──
    leak_violations, sanitized = _check_leakage(sanitized, policy, raw_data, filtered_context)
    violations.extend(leak_violations)

    # ── Check 3: Hallucination (data claims not in filtered context) ──
    hallucination_violations = _check_hallucination(sanitized, filtered_context, raw_data)
    violations.extend(hallucination_violations)

    # ── Determine decision ──
    if not violations:
        decision = "clean"
    else:
        severities = [v["severity"] for v in violations]
        if "critical" in severities:
            decision = "blocked"
            sanitized = (
                "[RESPONSE BLOCKED — Output governance detected critical violations. "
                f"{len(violations)} violation(s) caught. "
                "This interaction has been logged for compliance review.]"
            )
        else:
            decision = "redacted"

    return {
        "violations": violations,
        "sanitized_response": sanitized,
        "decision": decision,
    }


# ================================================================
# Check 1: Mask breaches
# ================================================================

def _check_mask_breaches(response: str, raw_data: dict) -> tuple[list[dict], str]:
    """Detect and redact SSN patterns and other masked field values in the response."""
    violations = []
    sanitized = response

    # Collect all real SSNs from the raw data for exact matching
    real_ssns = set()
    for person in raw_data.get("persons", []):
        ssn = person.get("ssn", "")
        if ssn:
            real_ssns.add(ssn)
            real_ssns.add(ssn.replace("-", ""))

    # Check for SSN patterns
    matches = _SSN_PATTERN.findall(sanitized)
    for match in matches:
        normalized = match.replace(" ", "-").replace(".", "-")
        no_dash = normalized.replace("-", "")

        is_real = normalized in real_ssns or no_dash in real_ssns

        violations.append({
            "type": "mask_breach",
            "description": f"SSN pattern detected in output{' (matches real record)' if is_real else ''}",
            "severity": "critical" if is_real else "high",
            "redacted_value": match[:3] + "...",
        })
        sanitized = sanitized.replace(match, "[SSN REDACTED]")

    return violations, sanitized


# ================================================================
# Check 2: Leakage — denied data values in output
# ================================================================

def _check_leakage(response: str, policy, raw_data: dict, filtered_context: str = "") -> tuple[list[dict], str]:
    """Detect denied data values appearing in the LLM response."""
    violations = []
    sanitized = response

    denied_values = _collect_denied_values(policy, raw_data)

    for value_info in denied_values:
        value_str = str(value_info["value"])

        # Skip very short values that would false-positive
        if len(value_str) < 4:
            continue

        if value_str in sanitized and value_str not in filtered_context:
            violations.append({
                "type": "leakage",
                "description": (
                    f"Denied {value_info['field']} from {value_info['resource']} "
                    f"detected in output"
                ),
                "severity": "high",
                "redacted_value": value_str[:6] + "...",
            })
            sanitized = sanitized.replace(value_str, f"[{value_info['field'].upper()} REDACTED]")

    # Also check for denied salary/financial figures as formatted currency
    currency_matches = _CURRENCY_PATTERN.findall(sanitized)
    denied_numbers = {v["value"] for v in denied_values if isinstance(v["value"], (int, float))}

    for match in currency_matches:
        try:
            amount = int(match.replace("$", "").replace(",", "").split(".")[0])
        except ValueError:
            continue

        if amount in denied_numbers and match not in filtered_context:
            violations.append({
                "type": "leakage",
                "description": f"Denied financial value ${amount:,} detected in output",
                "severity": "high",
                "redacted_value": match,
            })
            sanitized = sanitized.replace(match, "[FINANCIAL VALUE REDACTED]")

    return violations, sanitized


def _collect_denied_values(policy, raw_data: dict) -> list[dict]:
    """
    Collect specific data values from denied resources.
    These are the values that should NOT appear in the output.
    """
    denied_values = []
    metadata_keys = {"tenant_id", "data_source", "last_updated"}

    for resource_name in policy.denied_resources:
        records = raw_data.get(resource_name, [])
        if not isinstance(records, list):
            continue

        for record in records:
            if not isinstance(record, dict):
                continue
            for field, value in record.items():
                if value is None:
                    continue
                # Skip generic fields that cause false positives
                if field in _SKIP_FIELDS:
                    continue
                if isinstance(value, (int, float)) and value > 100:
                    denied_values.append({
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    })
                elif isinstance(value, str) and len(value) >= 6:
                    # Raised from 4 to 6 to skip short generic strings
                    denied_values.append({
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    })

    return denied_values


# ================================================================
# Check 3: Hallucination — claims not grounded in filtered context
# ================================================================

def _check_hallucination(response: str, filtered_context: str, raw_data: dict) -> list[dict]:
    """
    Detect when the LLM fabricates data-like claims not present
    in the filtered context it was given.
    """
    violations = []

    # Collect all numbers from the filtered context (what the LLM was given)
    context_numbers = set()
    for match in re.findall(r"\b\d{2,}\b", filtered_context.replace(",", "")):
        context_numbers.add(match)

    # Collect all numbers from the raw data (what actually exists)
    raw_numbers = {}
    metadata_keys = {"tenant_id", "data_source", "last_updated"}
    for resource_name, records in raw_data.items():
        if resource_name in metadata_keys or not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            for field, value in record.items():
                if isinstance(value, (int, float)) and value > 100:
                    raw_numbers[str(int(value))] = {
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    }

    # Find numbers in the response that exist in raw data but NOT in filtered context
    response_numbers = re.findall(r"\b\d{3,}\b", response.replace(",", ""))
    for num in response_numbers:
        if num in raw_numbers and num not in context_numbers:
            info = raw_numbers[num]
            violations.append({
                "type": "hallucination",
                "description": (
                    f"Response contains {info['field']}={info['value']} from "
                    f"{info['resource']} which was not in the authorized context — "
                    f"likely hallucinated from training data or inferred"
                ),
                "severity": "medium",
                "redacted_value": num,
            })

    # Check for plausible salary estimates near denied values
    currency_matches = _CURRENCY_PATTERN.findall(response)
    for match in currency_matches:
        try:
            amount = int(match.replace("$", "").replace(",", "").split(".")[0])
        except ValueError:
            continue

        amount_str = str(amount)
        # Skip if this amount is already in the authorized context
        if amount_str in context_numbers:
            continue

        for raw_num_str, info in raw_numbers.items():
            raw_val = info["value"]
            if isinstance(raw_val, (int, float)) and raw_val > 1000:
                if str(int(raw_val)) not in context_numbers:
                    if abs(amount - raw_val) / raw_val < 0.05 and match not in filtered_context:
                        violations.append({
                            "type": "hallucination",
                            "description": (
                                f"Response contains ${amount:,} which is within 5% of "
                                f"denied {info['field']}=${int(raw_val):,} — "
                                f"likely inferred from training data"
                            ),
                            "severity": "medium",
                            "redacted_value": match,
                        })
                        break

    return violations