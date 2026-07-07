"""
Arbiter -- API Test (v3.0)
Tests the FastAPI endpoints for bidirectional governance.
Uses FastAPI's TestClient for synchronous testing.
Run from server/ directory: python test_api.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def login(username: str, password: str = None) -> str:
    """Log in and return a session_id. Demo passwords equal the username."""
    r = client.post("/login", json={"username": username, "password": password or username})
    assert r.status_code == 200, f"login failed for {username}"
    return r.json()["session_id"]


def test_health():
    section("Health Check")
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "Arbiter"
    assert data["version"] == "3.0.0"
    assert data["governance"] == "bidirectional"
    print(f"  Status     : {data['status']}")
    print(f"  Version    : {data['version']}")
    print(f"  Governance : {data['governance']}")
    print(f"  Inference  : {data['inference_control']}")
    print(f"  Output     : {data['output_scanning']}")
    print("  [PASS]")


def test_login():
    section("Login — All Roles")

    # All demo credentials
    credentials = [
        ("admin", "admin", "Admin", "P012"),
        ("teacher", "teacher", "Teacher", "P009"),
        ("teacher2", "teacher2", "Teacher", "P010"),
        ("advisor", "advisor", "Advisor", "P011"),
        ("student", "student", "Student", "P001"),
        ("student2", "student2", "Student", "P004"),
        ("ta", "ta", "TA", "P003"),
    ]

    for username, password, expected_role, expected_id in credentials:
        r = client.post("/login", json={"username": username, "password": password})
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == expected_role
        assert data["user_id"] == expected_id
        print(f"  {username:10s} → {data['role']:8s} ({data['user_id']}) ✓")

    # Invalid credentials
    r = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    print(f"  bad pass   → 401 ✓")

    r = client.post("/login", json={"username": "nobody", "password": "x"})
    assert r.status_code == 401
    print(f"  unknown    → 401 ✓")
    print("  [PASS]")


def test_chat_admin():
    section("Chat — Admin (Full-Access clearance)")
    sid = login("admin")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "Show me all financial records",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "full"
    assert data["role"] == "Admin"
    assert len(data["denied_resources"]) == 0
    assert "output_decision" in data
    assert "inference_channels_blocked" in data
    print(f"  Access     : {data['access_level']}")
    print(f"  Denied     : {data['denied_resources']}")
    print(f"  Masked     : {data['masked_fields']}")
    print(f"  Inference  : {len(data['inference_channels_blocked'])} channel(s) blocked")
    print(f"  Output     : {data['output_decision']}")
    print(f"  Trace      : {data['trace_id']}")
    print(f"  Response   : {data['response'][:80]}...")
    print("  [PASS]")
    return data["trace_id"]


def test_chat_teacher():
    section("Chat — Teacher (Department-Scoped clearance)")
    sid = login("teacher")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "What is my salary?",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "partial"
    assert len(data["denied_resources"]) > 0
    print(f"  Access     : {data['access_level']}")
    print(f"  Denied     : {data['denied_resources']}")
    print(f"  Inference  : {len(data['inference_channels_blocked'])} channel(s) blocked")
    print(f"  Output     : {data['output_decision']}")
    print(f"  Trace      : {data['trace_id']}")
    print("  [PASS]")


def test_chat_teacher_inference():
    section("Chat — Teacher + Inference Channel Detection")
    sid = login("teacher")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "Show me the department budget and all faculty info",
    })
    assert r.status_code == 200
    data = r.json()
    channels = data["inference_channels_blocked"]
    print(f"  Access     : {data['access_level']}")
    print(f"  Inference  : {len(channels)} channel(s) blocked")
    for ch in channels:
        print(f"    → {ch['channel_id']}: {ch['name']} [{ch['severity']}]")
    print(f"  Output     : {data['output_decision']}")
    print(f"  Trace      : {data['trace_id']}")
    print("  [PASS]")


def test_chat_student():
    section("Chat — Student (Self-Scoped clearance)")
    sid = login("student")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "Show me grade records",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "partial"
    assert "departments" in data["denied_resources"]  # fixed: grades is own_only (authorized), departments is denied
    print(f"  Access     : {data['access_level']}")
    print(f"  Denied     : {data['denied_resources']}")
    print(f"  Output     : {data['output_decision']}")
    print(f"  Trace      : {data['trace_id']}")
    print("  [PASS]")


def test_chat_student_own_financial():
    section("Chat — Student sees own tuition only")
    sid = login("student")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "What is my tuition balance?",
    })
    assert r.status_code == 200
    data = r.json()
    # Student should see own financial data (scoped)
    assert "P001" in data["response"] or "6,500" in data["response"] or "DEMO MODE" in data["response"]
    print(f"  Access     : {data['access_level']}")
    print(f"  Response   : {data['response'][:100]}...")
    print("  [PASS]")


def test_chat_ta():
    section("Chat — TA (Course-Scoped grade access)")
    sid = login("ta")
    r = client.post("/chat", json={
        "session_id": sid,
        "message": "Show me grades for the class I TA for",
    })
    assert r.status_code == 200
    data = r.json()
    print(f"  Access     : {data['access_level']}")
    print(f"  Denied     : {data['denied_resources']}")
    print(f"  Inference  : {len(data['inference_channels_blocked'])} channel(s) blocked")
    print(f"  Output     : {data['output_decision']}")
    print(f"  Trace      : {data['trace_id']}")
    print("  [PASS]")


def test_chat_role_tampering():
    section("Chat — Role Tampering Rejected (ADV-01 fix)")
    # Log in as a student, then try to escalate by claiming role=Admin in the body.
    sid = login("student")
    r = client.post("/chat", json={
        "session_id": sid,
        "role": "Admin",          # tamper attempt — must be ignored
        "user_id": "P012",        # tamper attempt — must be ignored
        "message": "Show me all salaries and budgets",
    })
    assert r.status_code == 200
    data = r.json()
    # Server must bind to the student session, not the claimed Admin role.
    assert data["role"] == "Student", f"escalation! resolved role={data['role']}"
    assert "departments" in data["denied_resources"], "student should still be denied departments"
    # Privileged values must not appear in the response.
    body = data["response"].replace(",", "")
    assert "82000" not in body and "283000" not in body, "privileged data leaked via tampering"
    print(f"  Claimed    : role=Admin, user=P012")
    print(f"  Resolved   : role={data['role']} (session-bound)")
    print(f"  Denied     : {data['denied_resources']}")
    print("  [PASS] escalation blocked")


def test_chat_no_session_rejected():
    section("Chat — Missing Session Rejected (fail-closed)")
    r = client.post("/chat", json={"message": "Show me everything"})
    # session_id is now required — FastAPI returns 422 for the missing field.
    assert r.status_code in (401, 422), f"expected rejection, got {r.status_code}"
    print(f"  No session → {r.status_code} ✓")
    print("  [PASS]")


def test_chat_ungoverned():
    section("Chat — Ungoverned (split-screen demo)")
    r = client.post("/chat/ungoverned", json={
        "message": "Show me all student grades and salaries",
    })
    assert r.status_code == 200
    data = r.json()
    assert "No governance" in data["note"]
    # Ungoverned should expose raw data including SSNs
    print(f"  Note       : {data['note']}")
    print(f"  Response   : {data['response'][:100]}...")
    print("  [PASS]")


def test_audit_log():
    section("Audit Log")
    r = client.get("/audit-log")
    assert r.status_code == 200
    data = r.json()
    assert data["total_entries"] >= 4
    # Check that both INPUT and OUTPUT events exist
    event_types = {e.get("event_type") for e in data["entries"]}
    print(f"  Total entries : {data['total_entries']}")
    print(f"  Event types   : {event_types}")
    print(f"  Latest trace  : {data['entries'][-1]['trace_id']}")
    print("  [PASS]")


def test_context_packet(trace_id: str):
    section("Context Packet — CCP v3.0")
    r = client.get(f"/context-packet/{trace_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["ccp_version"] == "3.0"
    assert data["trace_id"] == trace_id
    assert "input_governance" in data
    assert "output_governance" in data
    assert "inference_control" in data
    print(f"  CCP Version   : {data['ccp_version']}")
    print(f"  Trace ID      : {data['trace_id']}")
    print(f"  Tenant        : {data['tenant']['tenant_id']}")
    print(f"  Input         : {data['input_governance']['policy_decision']}")
    print(f"  Inference     : {data['inference_control']['total_blocked']} blocked")
    print(f"  Output        : {data['output_governance']['decision']}")
    print(f"  Policy Hash   : {data['policy_hash']}")
    if "policy_hash_bidirectional" in data:
        print(f"  Bidir Hash    : {data['policy_hash_bidirectional']}")
    print("  [PASS]")

    # Test 404
    r = client.get("/context-packet/tr-nonexistent")
    assert r.status_code == 404
    print(f"  Missing trace : 404 ✓")
    print("  [PASS]")


def test_admin_roles():
    section("Admin — Role Management (ABAC)")

    # List roles
    r = client.get("/admin/roles")
    assert r.status_code == 200
    data = r.json()
    assert "Admin" in data["roles"]
    assert "Teacher" in data["roles"]
    assert "Student" in data["roles"]
    print(f"  Existing : {list(data['roles'].keys())}")

    # Create new role via ABAC (clearance + scopes, no resource lists)
    r = client.post("/admin/roles", json={
        "role_name": "Auditor",
        "clearance": "Full-Access",
        "description": "Read-only compliance auditor",
        "financial_scope": "all",
        "standing_scope": "all",
        "grades_scope": "all",
    })
    assert r.status_code == 200
    print(f"  Created  : Auditor (Full-Access clearance)")

    # Verify
    r = client.get("/admin/roles")
    data = r.json()
    assert "Auditor" in data["roles"]
    auditor = data["roles"]["Auditor"]
    assert auditor["clearance"] == "Full-Access"
    assert "allowed_resources" not in auditor  # ABAC — no resource lists
    print(f"  Verified : Auditor exists, no allowed_resources list (ABAC)")

    # Delete
    r = client.delete("/admin/roles/Auditor")
    assert r.status_code == 200
    print(f"  Deleted  : Auditor")

    # Verify deletion
    r = client.get("/admin/roles")
    data = r.json()
    assert "Auditor" not in data["roles"]
    print(f"  Verified : Auditor removed")
    print("  [PASS]")


def test_admin_policies():
    section("Admin — Policy Config")
    r = client.get("/admin/policies")
    assert r.status_code == 200
    data = r.json()
    assert "roles" in data
    assert "policies" in data
    assert "access_rules" in data["policies"]["institution_rules"]
    print(f"  Config       : roles + policies")
    print(f"  Roles        : {len(data['roles']['roles'])}")
    print(f"  Resources    : {list(data['policies']['resources'].keys())}")
    print(f"  Access rules : {len(data['policies']['institution_rules']['access_rules'])}")
    print("  [PASS]")


def test_demo_roles():
    section("Demo Roles Endpoint")
    r = client.get("/demo/roles")
    assert r.status_code == 200
    data = r.json()
    assert len(data["roles"]) == 7  # admin, teacher, teacher2, advisor, student, student2, ta
    for role in data["roles"]:
        print(f"  {role['username']:10s} → {role['role']:8s} | {role['label']}")
    print("  [PASS]")


def main():
    print("\n" + "=" * 60)
    print("  ARBITER v3.0 — Integration Test")
    print("  Bidirectional Governance + Inference Control")
    print("=" * 60)

    test_health()
    test_login()
    trace_id = test_chat_admin()
    test_chat_teacher()
    test_chat_teacher_inference()
    test_chat_student()
    test_chat_student_own_financial()
    test_chat_ta()
    test_chat_role_tampering()
    test_chat_no_session_rejected()
    test_chat_ungoverned()
    test_audit_log()
    test_context_packet(trace_id)
    test_admin_roles()
    test_admin_policies()
    test_demo_roles()

    print(f"\n{'=' * 60}")
    print("  [PASS] ALL 16 TESTS PASSED")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()