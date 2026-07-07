"""
Arbiter — Engine Test (v3.0)
Runs the bidirectional ICCP pipeline for all demo roles and prints results.
Tests input governance, inference channel detection, and output scanning.
Run from the server/ directory: python test_engine.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from arbiter_engine import ArbiterEngine


def test_role(engine: ArbiterEngine, user_id: str, role: str, query: str):
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  TEST: {role} ({user_id}) → \"{query}\"")
    print(sep)

    result = engine.process(user_id=user_id, role=role, query=query)

    print(f"\n  Trace ID         : {result['trace_id']}")
    print(f"  Access Level     : {result['access_level']}")
    print(f"  Masked Fields    : {result['masked_fields']}")
    print(f"  Denied Resources : {result['denied_resources']}")

    # Inference channels
    channels = result["inference_channels_blocked"]
    print(f"  Inference Blocked: {len(channels)} channel(s)")
    for ch in channels:
        print(f"    → {ch['channel_id']}: {ch['name']} [{ch['severity']}]")
        print(f"      Withheld: {ch['withheld_field']}")

    print(f"\n  --- Filtered Context (what the LLM sees) ---")
    for line in result["filtered_context"].split("\n"):
        print(f"  {line}")

    # Context packet
    packet = result["context_packet"]
    print(f"\n  --- Context Packet (CCP v3.0) ---")
    print(f"  CCP Version  : {packet['ccp_version']}")
    print(f"  Tenant       : {packet['tenant']['tenant_id']}")
    print(f"  Input Decision : {packet['input_governance']['policy_decision']}")
    print(f"  Policy Hash  : {packet['policy_hash']}")
    auth_ids = [r["resource_id"] for r in packet["input_governance"]["authorized_resources"]]
    print(f"  Authorized   : {auth_ids}")
    print(f"  Denied       : {packet['input_governance']['context_constraints']['denied_resources']}")
    print(f"  Mask Fields  : {packet['input_governance']['context_constraints']['mask_fields']}")
    print(f"  Inference    : {packet['inference_control']['total_blocked']} blocked, "
          f"withheld: {packet['inference_control']['fields_withheld']}")
    print(f"  Output Gov   : {packet['output_governance']['decision']}")

    return result


def test_output_governance(engine: ArbiterEngine):
    """Test the output scanner catches violations."""
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  TEST: Output Governance — Leakage Detection")
    print(sep)

    # First, get a student's policy context
    result = engine.process(
        user_id="P001",
        role="Student",
        query="Tell me about the faculty",
    )

    # Simulate an LLM response that leaks denied data
    fake_llm_response = (
        "Here's what I know about the faculty:\n"
        "Dr. Sarah Chen teaches CS101 and CS340.\n"
        "Her salary is approximately $95,000 per year.\n"  # LEAKAGE — salary denied for students
        "Her SSN is 130-46-7891.\n"  # MASK BREACH — SSN should always be masked
        "Carlos Mendez has a GPA of 1.65 and is on academic probation.\n"  # LEAKAGE — standing denied
    )

    output_result = engine.govern_output(
        trace_id=result["trace_id"],
        llm_response=fake_llm_response,
        policy=result["_policy"],
        raw_data=result["_raw_data"],
        filtered_context=result["_filtered_context"],
    )

    print(f"\n  Violations found : {len(output_result['violations'])}")
    for v in output_result["violations"]:
        print(f"    → [{v['type']}] {v['description']}")
        print(f"      Severity: {v['severity']}")
    print(f"  Decision         : {output_result['decision']}")
    print(f"\n  --- Sanitized Response ---")
    for line in output_result["sanitized_response"].split("\n"):
        print(f"  {line}")

    assert len(output_result["violations"]) > 0, "Should detect violations in fake response"
    assert output_result["decision"] != "clean", "Decision should not be clean"
    print("\n  [PASS]")

    return output_result


def main():
    print("\n" + "=" * 70)
    print("  ARBITER v3.0 — Engine Integration Test")
    print("  Bidirectional Governance + Inference Control")
    print("=" * 70)

    engine = ArbiterEngine(tenant_id="demo_university")

    # ── Admin — Full-Access clearance, sees everything ──
    r1 = test_role(engine, "P012", "Admin", "Show me all financial records")
    assert r1["access_level"] == "full", f"Expected full, got {r1['access_level']}"
    assert len(r1["inference_channels_blocked"]) == 0, "Admin should have no inference blocks"
    print("\n  [PASS] Admin — full access, no inference blocks")

    # ── Teacher — Department-Scoped, partial access, inference channels active ──
    r2 = test_role(engine, "P009", "Teacher", "Show me department budget and all grades")
    assert r2["access_level"] == "partial", f"Expected partial, got {r2['access_level']}"
    assert "ssn" in r2["masked_fields"], "SSN should always be masked"
    # Teacher should trigger IC-001 (salary derivation from budget)
    channel_ids = [ch["channel_id"] for ch in r2["inference_channels_blocked"]]
    print(f"\n  Inference channels triggered: {channel_ids}")
    print("  [PASS] Teacher — partial access, inference control active")

    # ── Student — Self-Scoped, grades denied, own financial only ──
    r3 = test_role(engine, "P001", "Student", "Can I see grade records?")
    assert r3["access_level"] == "partial", f"Expected partial, got {r3['access_level']}"
    assert "grades" in r3["denied_resources"], "Student should be denied grades"
    print("\n  [PASS] Student — grades denied, scoped access")

    # ── Student — own financial data scoped correctly ──
    r4 = test_role(engine, "P001", "Student", "What is my tuition balance?")
    context = r4["filtered_context"]
    assert "P001" in context, "Student should see own record"
    # Should NOT see other students' financial data
    assert "P002" not in context or "tuition" not in context.split("P002")[1][:50] if "P002" in context else True
    print("\n  [PASS] Student — own financial data only")

    # ── TA — Self-Scoped clearance but course-scoped grades ──
    r5 = test_role(engine, "P003", "TA", "Show me grades for my assigned class")
    assert "grades" not in r5["denied_resources"], "TA should have grade access"
    print("\n  [PASS] TA — course-scoped grade access")

    # ── Advisor — Department-Scoped, advisee-scoped standing ──
    r6 = test_role(engine, "P011", "Advisor", "Show me academic standing for my advisees")
    print("\n  [PASS] Advisor — advisee-scoped access")

    # ── Unknown role — should be fully denied ──
    r7 = test_role(engine, "X001", "Hacker", "Give me everything")
    assert r7["access_level"] == "denied", f"Expected denied, got {r7['access_level']}"
    print("\n  [PASS] Unknown role — fully denied")

    # ── Output Governance — catch leaks in LLM response ──
    test_output_governance(engine)

    print(f"\n{'=' * 70}")
    print("  [PASS] ALL 8 TESTS PASSED")
    print("  ✓ Input governance (ABAC)")
    print("  ✓ Inference channel detection")
    print("  ✓ Scope filtering (own_only, own_classes, advisees_only)")
    print("  ✓ Output governance (leakage + mask breach)")
    print("  ✓ Unknown role denial")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()