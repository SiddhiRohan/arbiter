"""
Arbiter -- API Test
Tests the FastAPI endpoints without needing a running server.
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


def test_health():
    section("Health Check")
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "Arbiter"
    assert data["version"] == "2.0.0"
    print(f"  Status  : {data['status']}")
    print(f"  Service : {data['service']}")
    print(f"  Version : {data['version']}")
    print(f"  Tenant  : {data['tenant']}")
    print(f"  ICCP    : {data['iccp']}")
    print("  [PASS]")


def test_login():
    section("Login")

    # Valid login
    r = client.post("/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "Admin"
    assert data["label"] == "Robert Torres"
    print(f"  Admin login  : OK (session={data['session_id'][:16]}...)")

    # Invalid login
    r = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401
    print(f"  Bad password  : Correctly rejected (401)")

    # Unknown user
    r = client.post("/login", json={"username": "nobody", "password": "x"})
    assert r.status_code == 401
    print(f"  Unknown user  : Correctly rejected (401)")
    print("  [PASS]")


def test_chat_admin():
    section("Chat -- Admin (full access)")
    r = client.post("/chat", json={
        "user_id": "P003",
        "role": "Admin",
        "message": "Show me all financial records",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "full"
    assert data["role"] == "Admin"
    assert len(data["denied_resources"]) == 0
    print(f"  Access   : {data['access_level']}")
    print(f"  Denied   : {data['denied_resources']}")
    print(f"  Masked   : {data['masked_fields']}")
    print(f"  Trace    : {data['trace_id']}")
    print(f"  Response : {data['response'][:80]}...")
    print("  [PASS]")
    return data["trace_id"]


def test_chat_teacher():
    section("Chat -- Teacher (partial access)")
    r = client.post("/chat", json={
        "user_id": "P002",
        "role": "Teacher",
        "message": "What is my salary?",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "partial"
    assert "financial_information_others" in data["denied_resources"]
    print(f"  Access   : {data['access_level']}")
    print(f"  Denied   : {data['denied_resources']}")
    print(f"  Trace    : {data['trace_id']}")
    print("  [PASS]")


def test_chat_student():
    section("Chat -- Student (grades denied)")
    r = client.post("/chat", json={
        "user_id": "P001",
        "role": "Student",
        "message": "Show me grade records",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["access_level"] == "partial"
    assert "grades" in data["denied_resources"]
    print(f"  Access   : {data['access_level']}")
    print(f"  Denied   : {data['denied_resources']}")
    print(f"  Trace    : {data['trace_id']}")
    print("  [PASS]")


def test_audit_log():
    section("Audit Log")
    r = client.get("/audit-log")
    assert r.status_code == 200
    data = r.json()
    assert data["total_entries"] >= 3
    print(f"  Total entries : {data['total_entries']}")
    print(f"  Latest trace  : {data['entries'][-1]['trace_id']}")
    print("  [PASS]")


def test_context_packet(trace_id: str):
    section("Context Packet Retrieval")
    r = client.get(f"/context-packet/{trace_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["ccp_version"] == "2.0"
    assert data["trace_id"] == trace_id
    print(f"  CCP Version  : {data['ccp_version']}")
    print(f"  Trace ID     : {data['trace_id']}")
    print(f"  Tenant       : {data['tenant']['tenant_id']}")
    print(f"  Decision     : {data['policy_decision']}")
    print(f"  Policy Hash  : {data['policy_hash']}")
    print("  [PASS]")

    # Test 404
    r = client.get("/context-packet/tr-nonexistent")
    assert r.status_code == 404
    print(f"  Missing trace : Correctly returned 404")
    print("  [PASS]")


def test_admin_roles():
    section("Admin -- Role Management")

    # List roles
    r = client.get("/admin/roles")
    assert r.status_code == 200
    data = r.json()
    assert "Admin" in data["roles"]
    assert "Teacher" in data["roles"]
    assert "Student" in data["roles"]
    print(f"  Existing roles : {list(data['roles'].keys())}")

    # Create new role
    r = client.post("/admin/roles", json={
        "role_name": "Auditor",
        "clearance": "Read-Only",
        "description": "Can view all data but not modify",
        "allowed_resources": ["persons", "grades", "classes"],
        "can_view_grades": True,
    })
    assert r.status_code == 200
    print(f"  Created role   : Auditor")

    # Verify it exists
    r = client.get("/admin/roles")
    data = r.json()
    assert "Auditor" in data["roles"]
    print(f"  Verified       : Auditor in roles list")

    # Delete it
    r = client.delete("/admin/roles/Auditor")
    assert r.status_code == 200
    print(f"  Deleted role   : Auditor")

    # Verify deletion
    r = client.get("/admin/roles")
    data = r.json()
    assert "Auditor" not in data["roles"]
    print(f"  Verified       : Auditor removed")
    print("  [PASS]")


def test_admin_policies():
    section("Admin -- Policy Config")
    r = client.get("/admin/policies")
    assert r.status_code == 200
    data = r.json()
    assert "roles" in data
    assert "policies" in data
    print(f"  Config loaded  : roles + policies")
    print(f"  Roles count    : {len(data['roles']['roles'])}")
    print(f"  Resources      : {list(data['policies']['resources'].keys())}")
    print("  [PASS]")


def test_demo_roles():
    section("Demo Roles Endpoint")
    r = client.get("/demo/roles")
    assert r.status_code == 200
    data = r.json()
    assert len(data["roles"]) == 3
    for role in data["roles"]:
        print(f"  {role['role']:8s} | {role['label']:16s} | {role['username']}")
    print("  [PASS]")


def main():
    print("\n" + "=" * 60)
    print("  ARBITER API -- Integration Test")
    print("=" * 60)

    test_health()
    test_login()
    trace_id = test_chat_admin()
    test_chat_teacher()
    test_chat_student()
    test_audit_log()
    test_context_packet(trace_id)
    test_admin_roles()
    test_admin_policies()
    test_demo_roles()

    print(f"\n{'=' * 60}")
    print("  [PASS] ALL API TESTS PASSED")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
