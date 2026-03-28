"""
Arbiter — Engine Test
Runs the ICCP pipeline for all three demo roles and prints the results.
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
    print(f"  TEST: {role} ({user_id}) -> \"{query}\"")
    print(sep)

    result = engine.process(user_id=user_id, role=role, query=query)

    print(f"\n  Trace ID        : {result['trace_id']}")
    print(f"  Access Level    : {result['access_level']}")
    print(f"  Masked Fields   : {result['masked_fields']}")
    print(f"  Denied Resources: {result['denied_resources']}")
    print(f"\n  --- Filtered Context (what the LLM sees) ---")
    for line in result["filtered_context"].split("\n"):
        print(f"  {line}")

    print(f"\n  --- Context Packet (CCP v2.0) ---")
    packet = result["context_packet"]
    print(f"  CCP Version  : {packet['ccp_version']}")
    print(f"  Tenant       : {packet['tenant']['tenant_id']}")
    print(f"  Decision     : {packet['policy_decision']}")
    print(f"  Policy Hash  : {packet['policy_hash']}")
    print(f"  Authorized   : {[r['resource_id'] for r in packet['authorized_resources']]}")
    print(f"  Denied       : {packet['context_constraints']['denied_resources']}")
    print(f"  Mask Fields  : {packet['context_constraints']['mask_fields']}")

    return result


def main():
    print("\n" + "=" * 70)
    print("  ARBITER ENGINE — Integration Test")
    print("  Running ICCP pipeline for all demo roles")
    print("=" * 70)

    engine = ArbiterEngine(tenant_id="demo_university")

    # Admin — should see everything
    r1 = test_role(engine, "P003", "Admin", "Show me all financial records")
    assert r1["access_level"] == "full", f"Admin should have full access, got {r1['access_level']}"

    # Teacher — should see grades, classes, own salary only
    r2 = test_role(engine, "P002", "Teacher", "Show me all grades and my salary")
    assert r2["access_level"] == "partial", f"Teacher should have partial access, got {r2['access_level']}"
    assert "ssn" in r2["masked_fields"], "SSN should always be masked"

    # Student — should NOT see grades, should see own tuition only
    r3 = test_role(engine, "P001", "Student", "Can I see grade records?")
    assert r3["access_level"] == "partial", f"Student should have partial access, got {r3['access_level']}"
    assert "grades" in r3["denied_resources"], "Student should be denied grades access"

    print(f"\n{'=' * 70}")
    print("  [PASS] ALL TESTS PASSED")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
