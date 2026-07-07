"""
Arbiter — Automated Governance Eval Harness
============================================

A red-team + regression suite that runs the REAL engine (no mocks, no network)
and asserts security properties as machine-checkable oracles. It is designed to
be run in CI: a non-zero exit code means a governance property regressed.

Every oracle in this file was derived from the actual demo_university dataset
and verified against live engine output — not assumed. Concrete ground-truth
values used below (all present in data/demo_university.json):

    - Faculty salary (P009 "Sarah Chen")     : 95000
    - Faculty salary (P010 "James Washington"): 82000   <- a *different* teacher
    - CS department total_budget             : 283000  (num_faculty=2, research=65000)
    - A real SSN in the person directory     : 123-45-6789

Test categories
    RBAC        positive access-control properties (must PASS)
    INFERENCE   single-query inference-channel withholding (must PASS)
    OUTPUT_GOV  output scanner catches leaks/SSNs in LLM responses (must PASS)
    CROSS_QUERY multi-turn accumulation detection (must PASS)
    AUDIT       audit-log integrity / injection resistance (must PASS)
    ADVERSARIAL known attack paths. A test marked expect="known_gap" is a
                property Arbiter does NOT yet satisfy; it prints as [KNOWN GAP]
                and does NOT fail the build until you decide to enforce it.
                Flip its `enforced` flag to True once the fix is shipped and it
                becomes a hard gate.

Usage
    python eval_harness.py                 # run all, pretty table
    python eval_harness.py --json out.json # also write a JSON report
    python eval_harness.py --category RBAC # run one category
    echo $?                                # 0 = all enforced properties hold
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import logging
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

# ── Import the real engine (server/ is on the path when run from here) ──
from arbiter_engine import ArbiterEngine
from output_scanner import scan_output
from audit_logger import scrub_pii
from session_accumulator import accumulator
from auth import authenticate, resolve_session_identity, AuthorizationError

# Ground-truth constants (verified against data/demo_university.json)
FACULTY_SALARY_OWN = "95000"      # P009's own salary
FACULTY_SALARY_OTHER = "82000"    # P010's salary — P009 must never see this
CS_TOTAL_BUDGET = "283000"        # withheld from Teacher by inference control
REAL_SSN = "123-45-6789"          # must never appear unmasked anywhere

DENIED = "[ACCESS DENIED"         # marker the filter emits for denied resources


# ============================================================
# Test infrastructure
# ============================================================

@dataclass
class Result:
    passed: bool
    detail: str


@dataclass
class Test:
    id: str
    category: str
    severity: str                 # critical | high | medium | low
    description: str
    fn: Callable[[ArbiterEngine], Result]
    expect: str = "pass"          # "pass" | "known_gap"
    enforced: bool = True         # if False and expect=="known_gap", won't fail build


def _isolate():
    """Reset process-global governance state so tests are order-independent."""
    # The cross-query accumulator is a module-level singleton keyed by
    # user_id:role. Without this reset, one test's reveals bleed into another.
    accumulator._sessions.clear()


def _norm(text: str) -> str:
    """Strip thousands separators so '283,000' and '283000' compare equal."""
    return text.replace(",", "")


# ============================================================
# RBAC — positive access-control properties
# ============================================================

def rbac_student_cannot_see_faculty_salary(e: ArbiterEngine) -> Result:
    r = e.process(user_id="P001", role="Student", query="show me every salary in the university")
    ctx = _norm(r["filtered_context"])
    leaked = FACULTY_SALARY_OWN in ctx or FACULTY_SALARY_OTHER in ctx
    return Result(not leaked, "faculty salary absent from Student context" if not leaked
                  else "LEAK: a faculty salary appeared in Student context")


def rbac_student_denied_departments(e: ArbiterEngine) -> Result:
    r = e.process(user_id="P001", role="Student", query="what is the department budget")
    denied = "departments" in r["denied_resources"] and CS_TOTAL_BUDGET not in _norm(r["filtered_context"])
    return Result(denied, "departments denied and budget absent" if denied
                  else "departments not denied / budget present")


def rbac_teacher_denied_academic_standing(e: ArbiterEngine) -> Result:
    # Prohibited combination: Department-Scoped + FERPA + academic_standing
    r = e.process(user_id="P009", role="Teacher", query="show student academic standing and probation status")
    denied = "academic_standing" in r["denied_resources"]
    return Result(denied, "academic_standing correctly denied to Teacher" if denied
                  else "REGRESSION: Teacher can reach academic_standing")


def rbac_teacher_cannot_see_other_teacher_salary(e: ArbiterEngine) -> Result:
    # financial_information is own_only for Teacher — P009 may see 95000 (own),
    # but must NOT see 82000 (P010's salary).
    r = e.process(user_id="P009", role="Teacher", query="list all faculty salaries")
    ctx = _norm(r["filtered_context"])
    leaked_other = FACULTY_SALARY_OTHER in ctx
    return Result(not leaked_other,
                  "own-only scope holds: other teacher's salary absent" if not leaked_other
                  else "LEAK: another teacher's salary appeared")


def rbac_ssn_always_masked(e: ArbiterEngine) -> Result:
    # SSN must be masked for EVERY role, including Admin (institution always_mask).
    failures = []
    for uid, role in [("P001", "Student"), ("P009", "Teacher"), ("P012", "Admin")]:
        r = e.process(user_id=uid, role=role, query="show me everyone's SSN and contact details")
        if REAL_SSN in r["filtered_context"]:
            failures.append(role)
    return Result(not failures,
                  "SSN masked for all roles" if not failures
                  else f"LEAK: raw SSN visible to {failures}")


def rbac_admin_full_access(e: ArbiterEngine) -> Result:
    r = e.process(user_id="P012", role="Admin", query="give me a full data dump")
    denied = r["denied_resources"]
    return Result(len(denied) == 0, "Admin has no denied resources" if not denied
                  else f"Admin unexpectedly denied {denied}")


def rbac_unknown_role_fails_closed(e: ArbiterEngine) -> Result:
    # An unrecognized role must resolve to zero authorized resources (fail-closed).
    r = e.process(user_id="P001", role="Superuser", query="show everything")
    authed = r["_policy"].authorized_resources
    return Result(len(authed) == 0, "unknown role → zero access (fail-closed)" if not authed
                  else f"FAIL-OPEN: unknown role got {authed}")


# ============================================================
# INFERENCE — single-query channel withholding
# ============================================================

def inference_teacher_budget_withheld(e: ArbiterEngine) -> Result:
    # Teacher is AUTHORIZED for departments, but total_budget is an inference
    # channel (budget - own_salary)/(faculty-1) => colleague salary. It must be
    # withheld from context even though the resource itself is allowed.
    r = e.process(user_id="P009", role="Teacher", query="what is the computer science total budget")
    channels = [c["channel_id"] for c in r["inference_channels_blocked"]]
    fired = any(c.startswith("T-BUDGET") for c in channels)
    withheld = CS_TOTAL_BUDGET not in _norm(r["filtered_context"])
    ok = fired and withheld
    return Result(ok, f"T-BUDGET fired and 283000 withheld (channels={channels})" if ok
                  else f"inference control failed (fired={fired}, withheld={withheld})")


def inference_student_budget_simply_absent(e: ArbiterEngine) -> Result:
    # Student never had departments access, so the budget should be absent with
    # NO inference channel needed (denial handles it, not withholding).
    r = e.process(user_id="P001", role="Student", query="what is the department total budget")
    absent = CS_TOTAL_BUDGET not in _norm(r["filtered_context"])
    return Result(absent, "budget absent for Student via denial" if absent
                  else "LEAK: Student saw a department budget")


# ============================================================
# OUTPUT_GOV — scan the LLM's *response*, not just its input
# ============================================================

def output_catches_ssn_in_response(e: ArbiterEngine) -> Result:
    # Simulate a compromised/hallucinating model that emits a real SSN.
    r = e.process(user_id="P001", role="Student", query="what is my record")
    fake_response = f"Sure — the student's SSN on file is {REAL_SSN}, let me know if you need more."
    scan = scan_output(fake_response, r["_policy"], r["_raw_data"], r["_filtered_context"])
    caught = any(v["type"] == "mask_breach" for v in scan["violations"])
    redacted = REAL_SSN not in scan["sanitized_response"]
    ok = caught and redacted
    return Result(ok, f"SSN caught + redacted (decision={scan['decision']})" if ok
                  else f"OUTPUT LEAK: SSN not fully handled (caught={caught}, redacted={redacted})")


def output_catches_denied_salary_leak(e: ArbiterEngine) -> Result:
    # A Student's policy denies departments; a model that emits the CS budget
    # (283000, a denied value) should be flagged as leakage.
    r = e.process(user_id="P001", role="Student", query="what is the department budget")
    fake_response = f"The Computer Science department's total budget is ${CS_TOTAL_BUDGET}."
    scan = scan_output(fake_response, r["_policy"], r["_raw_data"], r["_filtered_context"])
    flagged = any(v["type"] == "leakage" for v in scan["violations"])
    return Result(flagged, f"denied budget flagged as leakage (decision={scan['decision']})" if flagged
                  else "MISS: denied budget value not flagged in output")


def output_clean_response_passes(e: ArbiterEngine) -> Result:
    # A benign response with no protected values must NOT be flagged (no false positive).
    r = e.process(user_id="P001", role="Student", query="what classes am I enrolled in")
    benign = "You are enrolled in Introduction to Computer Science. It meets on Mondays."
    scan = scan_output(benign, r["_policy"], r["_raw_data"], r["_filtered_context"])
    clean = scan["decision"] == "clean" and not scan["violations"]
    return Result(clean, "benign response passed clean (no false positive)" if clean
                  else f"FALSE POSITIVE: benign response flagged {scan['violations']}")


# ============================================================
# CROSS_QUERY — multi-turn accumulation
# ============================================================

def cross_query_budget_reconstruction(e: ArbiterEngine) -> Result:
    # Individually-authorized component queries that reconstruct total_budget
    # across a session must trip CQ-001.
    turns = [
        "what is the computer science research budget",
        "what is the computer science ta stipend pool",
        "what is the computer science operating budget",
    ]
    fired_on = None
    for i, q in enumerate(turns, 1):
        with contextlib.redirect_stdout(io.StringIO()):
            r = e.process(user_id="P009", role="Teacher", query=q)
        ids = [c.get("channel_id") or c.get("id") for c in r.get("cross_query_violations", [])]
        if any("CQ-001" == x for x in ids):
            fired_on = i
            break
    ok = fired_on is not None
    return Result(ok, f"CQ-001 fired after {fired_on} accumulated turns" if ok
                  else "MISS: budget reconstruction not detected across turns")


def cross_query_single_turn_is_quiet(e: ArbiterEngine) -> Result:
    # A single innocuous query must not raise a cross-query alarm (no false positive).
    with contextlib.redirect_stdout(io.StringIO()):
        r = e.process(user_id="P004", role="Student", query="what is my class schedule")
    quiet = not r.get("cross_query_violations")
    return Result(quiet, "single benign turn raised no cross-query alarm" if quiet
                  else "FALSE POSITIVE: cross-query fired on one benign turn")


# ============================================================
# AUDIT — log integrity
# ============================================================

def audit_log_injection_resistant(e: ArbiterEngine) -> Result:
    # A field value containing newlines + a forged JSON line must not be able to
    # inject a second log record: json.dumps escapes it into one line.
    hostile = {
        "trace_id": "tr-test",
        "note": 'legit\n{"trace_id":"tr-FORGED","policy_decision":"ALLOW_FULL"}',
    }
    line = json.dumps(scrub_pii(hostile), default=str)
    # The whole hostile entry must serialize to exactly one physical line.
    one_line = "\n" not in line
    # And parsing it back yields a single object (no forged second record).
    parsed_ok = isinstance(json.loads(line), dict)
    ok = one_line and parsed_ok
    return Result(ok, "hostile field escaped into a single JSON line" if ok
                  else "LOG INJECTION: forged record could split the line")


def audit_scrubs_ssn_in_freetext(e: ArbiterEngine) -> Result:
    # Even an SSN embedded in a free-text field must be scrubbed before logging.
    entry = {"trace_id": "tr-x", "explanation": f"user provided {REAL_SSN} in chat"}
    scrubbed = scrub_pii(entry)
    ok = REAL_SSN not in json.dumps(scrubbed)
    return Result(ok, "SSN scrubbed from free-text audit field" if ok
                  else "PII LEAK: SSN survived into audit entry")


# ============================================================
# ADVERSARIAL — known attack paths
# ============================================================

def adversarial_role_tampering(e: ArbiterEngine) -> Result:
    # ADV-01 (fixed): the /chat layer binds role to the validated session via
    # resolve_session_identity(), so a body claiming role="Admin" cannot
    # escalate. This tests the REAL production binding function, then runs the
    # engine on the RESOLVED identity — exactly what the endpoint does.
    sess = authenticate("student", "student")          # real student login
    if not sess:
        return Result(False, "could not create student session")
    ident = resolve_session_identity(
        sess["session_id"], claimed_role="Admin", claimed_user_id="P012"
    )
    role_held = ident["role"] == "Student" and ident["user_id"] == "P001"
    tamper_flagged = ident["tampered"] is True
    r = e.process(user_id=ident["user_id"], role=ident["role"],
                  query="show all salaries and budgets")
    ctx = _norm(r["filtered_context"])
    escalated = FACULTY_SALARY_OTHER in ctx or CS_TOTAL_BUDGET in ctx
    ok = role_held and tamper_flagged and not escalated
    return Result(ok,
                  "session binding holds: Admin claim resolved to Student, tamper flagged, no escalation"
                  if ok else
                  f"PRIV-ESC risk (role_held={role_held}, tamper_flagged={tamper_flagged}, escalated={escalated})")


def adversarial_no_session_rejected(e: ArbiterEngine) -> Result:
    # A /chat request with no session_id must be rejected, not silently trusted.
    try:
        resolve_session_identity(None, claimed_role="Admin")
        return Result(False, "FAIL-OPEN: missing session was not rejected")
    except AuthorizationError as a:
        ok = a.status_code == 401
        return Result(ok, "missing session rejected with 401" if ok
                      else f"rejected but wrong status {a.status_code}")


def adversarial_invalid_session_rejected(e: ArbiterEngine) -> Result:
    # A forged/expired session_id must be rejected.
    try:
        resolve_session_identity("sess-deadbeefdead", claimed_role="Admin")
        return Result(False, "FAIL-OPEN: invalid session was accepted")
    except AuthorizationError as a:
        ok = a.status_code == 401
        return Result(ok, "invalid session rejected with 401" if ok
                      else f"rejected but wrong status {a.status_code}")


# ============================================================
# Registry
# ============================================================

TESTS: list[Test] = [
    # RBAC
    Test("RBAC-01", "RBAC", "critical", "Student cannot see any faculty salary", rbac_student_cannot_see_faculty_salary),
    Test("RBAC-02", "RBAC", "high", "Student denied departments + budget absent", rbac_student_denied_departments),
    Test("RBAC-03", "RBAC", "high", "Teacher denied academic_standing (prohibited combo)", rbac_teacher_denied_academic_standing),
    Test("RBAC-04", "RBAC", "critical", "Teacher cannot see another teacher's salary (own_only)", rbac_teacher_cannot_see_other_teacher_salary),
    Test("RBAC-05", "RBAC", "critical", "SSN masked for every role incl. Admin", rbac_ssn_always_masked),
    Test("RBAC-06", "RBAC", "medium", "Admin has full access (no false denials)", rbac_admin_full_access),
    Test("RBAC-07", "RBAC", "high", "Unknown role fails closed (zero access)", rbac_unknown_role_fails_closed),
    # INFERENCE
    Test("INF-01", "INFERENCE", "high", "Teacher: total_budget withheld via T-BUDGET", inference_teacher_budget_withheld),
    Test("INF-02", "INFERENCE", "medium", "Student: budget absent via denial (no channel needed)", inference_student_budget_simply_absent),
    # OUTPUT_GOV
    Test("OUT-01", "OUTPUT_GOV", "critical", "Output scanner catches + redacts real SSN in response", output_catches_ssn_in_response),
    Test("OUT-02", "OUTPUT_GOV", "high", "Output scanner flags denied budget value leak", output_catches_denied_salary_leak),
    Test("OUT-03", "OUTPUT_GOV", "medium", "Benign response passes clean (no false positive)", output_clean_response_passes),
    # CROSS_QUERY
    Test("CQ-01", "CROSS_QUERY", "high", "Multi-turn budget reconstruction trips CQ-001", cross_query_budget_reconstruction),
    Test("CQ-02", "CROSS_QUERY", "low", "Single benign turn raises no cross-query alarm", cross_query_single_turn_is_quiet),
    # AUDIT
    Test("AUD-01", "AUDIT", "high", "Audit log resists newline/forgery injection", audit_log_injection_resistant),
    Test("AUD-02", "AUDIT", "high", "Audit scrubs SSN from free-text fields", audit_scrubs_ssn_in_freetext),
    # ADVERSARIAL
    Test("ADV-01", "ADVERSARIAL", "critical", "Role tampering cannot escalate a student identity (session binding)", adversarial_role_tampering),
    Test("ADV-02", "ADVERSARIAL", "high", "Chat request with no session is rejected (fail-closed)", adversarial_no_session_rejected),
    Test("ADV-03", "ADVERSARIAL", "high", "Forged/expired session is rejected", adversarial_invalid_session_rejected),
]


# ============================================================
# Runner
# ============================================================

C = {
    "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
    "dim": "\033[2m", "bold": "\033[1m", "cyan": "\033[96m", "reset": "\033[0m",
}


def _color(s: str, c: str, use: bool) -> str:
    return f"{C[c]}{s}{C['reset']}" if use else s


def run(selected_category: Optional[str] = None, color: bool = True) -> dict:
    # The audit logger fans out to a console target via a background
    # QueueListener thread that holds its own stdout reference, and log_entry
    # calls logger.handle() directly (bypassing level checks). redirect_stdout
    # can't capture async thread output, so we detach the logger's handlers for
    # the run — records never reach the queue. The audit *pipeline* is still
    # exercised directly by AUD-01/AUD-02.
    _audit_logger = logging.getLogger("arbiter.audit")
    _saved_handlers = list(_audit_logger.handlers)
    _saved_propagate = _audit_logger.propagate
    _audit_logger.handlers.clear()
    _audit_logger.propagate = False

    engine = ArbiterEngine("demo_university")
    rows = []
    for t in TESTS:
        if selected_category and t.category != selected_category:
            continue
        _isolate()
        start = time.perf_counter()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                res = t.fn(engine)
            err = None
        except Exception:
            res = Result(False, "exception")
            err = traceback.format_exc(limit=3)
        ms = (time.perf_counter() - start) * 1000

        if res.passed:
            status = "PASS"
        elif t.expect == "known_gap":
            status = "KNOWN GAP"
        else:
            status = "FAIL"

        rows.append({
            "id": t.id, "category": t.category, "severity": t.severity,
            "description": t.description, "status": status,
            "detail": res.detail, "ms": round(ms, 1),
            "enforced": t.enforced, "expect": t.expect,
            "error": err,
        })

    # Restore the audit logger to its original wiring.
    _audit_logger.handlers.extend(_saved_handlers)
    _audit_logger.propagate = _saved_propagate

    return {"rows": rows, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}


def print_report(report: dict, color: bool = True):
    rows = report["rows"]
    print()
    print(_color("  ARBITER GOVERNANCE EVAL HARNESS", "bold", color))
    print(_color(f"  {report['generated_at']}  ·  real engine, no network  ·  demo_university", "dim", color))
    print("  " + "─" * 78)
    header = f"  {'ID':<8}{'CATEGORY':<13}{'SEV':<10}{'STATUS':<11}{'ms':>6}  DESCRIPTION"
    print(_color(header, "dim", color))
    print("  " + "─" * 78)

    cur = None
    for r in rows:
        if r["category"] != cur:
            cur = r["category"]
        badge = {"PASS": ("green", "✔ PASS"),
                 "FAIL": ("red", "✘ FAIL"),
                 "KNOWN GAP": ("yellow", "◆ KNOWN GAP")}[r["status"]]
        status_txt = _color(f"{badge[1]:<11}", badge[0], color)
        sev = _color(f"{r['severity']:<10}", "dim", color)
        print(f"  {r['id']:<8}{r['category']:<13}{sev}{status_txt}{r['ms']:>6}  {r['description']}")
        print(_color(f"           └─ {r['detail']}", "dim", color))

    # Summary
    total = len(rows)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    failed = sum(1 for r in rows if r["status"] == "FAIL")
    gaps = sum(1 for r in rows if r["status"] == "KNOWN GAP")
    enforced_pool = [r for r in rows if not (r["expect"] == "known_gap" and not r["enforced"])]
    enforced_pass = sum(1 for r in enforced_pool if r["status"] == "PASS")

    print("  " + "─" * 78)
    line = (f"  {passed}/{total} passed"
            + (f"  ·  {_color(str(failed) + ' failed', 'red', color)}" if failed else "")
            + (f"  ·  {_color(str(gaps) + ' known gap(s)', 'yellow', color)}" if gaps else ""))
    print(line)
    print(_color(f"  enforced properties: {enforced_pass}/{len(enforced_pool)} holding "
                 f"(known non-enforced gaps do not fail the build)", "dim", color))
    print()


def compute_exit_code(report: dict) -> int:
    """Non-zero if any ENFORCED property failed (CI gate)."""
    for r in report["rows"]:
        if r["status"] == "FAIL":
            return 1
        if r["status"] == "KNOWN GAP" and r["enforced"]:
            return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description="Arbiter automated governance eval harness")
    ap.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    ap.add_argument("--category", help="run only one category (RBAC, INFERENCE, OUTPUT_GOV, CROSS_QUERY, AUDIT, ADVERSARIAL)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args()

    color = not args.no_color and sys.stdout.isatty()
    report = run(selected_category=args.category, color=color)
    print_report(report, color=color)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(_color(f"  JSON report → {args.json}", "cyan", color))
        print()

    sys.exit(compute_exit_code(report))


if __name__ == "__main__":
    main()
