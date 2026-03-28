"""
Arbiter — Data Filter
Takes raw tenant data + a PolicyDecision, returns only what the user is allowed to see.
Handles field masking (SSN --> ***), record scoping (own-only), and access denial.
Designed to be data-schema agnostic — the filtering rules come from the policy, not hardcoded logic.
"""

import copy
from typing import Any

from policy_engine import PolicyDecision


def filter_data(
    raw_data: dict,
    policy: PolicyDecision,
    role: str,
    user_id: str,
    role_config: dict,
) -> dict:
    """
    Apply policy-based filtering to raw tenant data.
    Returns a new dict containing only authorized, masked, scoped data.
    """
    filtered = {}

    # Persons — available to most roles, but with field masking
    if "persons" in policy.authorized_resources:
        persons = copy.deepcopy(raw_data.get("persons", []))
        for person in persons:
            _apply_masks(person, policy.mask_fields)
        filtered["persons"] = persons

    # Financial information — scoped based on role config
    if "financial_information" in policy.authorized_resources:
        financials = copy.deepcopy(raw_data.get("financial_information", []))
        scope = role_config.get("financial_scope")

        if role_config.get("can_view_others_financial", False):
            filtered["financial_information"] = financials
        elif scope == "own_only":
            own_records = [f for f in financials if f.get("person_id") == user_id]
            filtered["financial_information"] = own_records
            filtered["financial_information_note"] = _scope_note(role)
        else:
            filtered["financial_information"] = "[ACCESS DENIED]"
    else:
        filtered["financial_information"] = "[ACCESS DENIED — Your role cannot access financial records.]"

    # Grades — binary access (allowed or denied)
    if "grades" in policy.authorized_resources:
        filtered["grades"] = copy.deepcopy(raw_data.get("grades", []))
    else:
        filtered["grades"] = "[ACCESS DENIED — Your role cannot access grade records.]"

    # Classes — allowed for most roles, but students get a limited view
    if "classes" in policy.authorized_resources:
        classes = copy.deepcopy(raw_data.get("classes", []))
        if role == "Student":
            filtered["classes"] = [_student_class_view(c) for c in classes]
        else:
            filtered["classes"] = classes
    else:
        filtered["classes"] = "[ACCESS DENIED]"

    return filtered


def _apply_masks(record: dict, mask_fields: list[str]) -> None:
    """Replace masked field values with redaction markers in-place."""
    for field in mask_fields:
        if field in record:
            record[field] = "***-**-****" if field == "ssn" else "[MASKED]"


def _student_class_view(class_record: dict) -> dict:
    """Return a limited view of class data for students (no internal notes, etc)."""
    return {
        "class_id": class_record.get("class_id"),
        "name": class_record.get("name"),
        "teacher_name": class_record.get("teacher_name"),
        "schedule": class_record.get("schedule"),
        "room": class_record.get("room"),
        "credits": class_record.get("credits"),
        "enrolled_students": class_record.get("enrolled_students", []),
    }


def _scope_note(role: str) -> str:
    """Human-readable note explaining why financial data is scoped."""
    if role == "Teacher":
        return "Restricted to your own salary record only."
    elif role == "Student":
        return "Restricted to your own tuition information only."
    return "Financial data has been scoped to your own records."


def to_text(filtered_data: dict) -> str:
    """
    Convert filtered data dict into a readable text block for the LLM context.
    This is what the AI model actually sees.
    """
    sections = []

    if "persons" in filtered_data:
        section = ["=== PERSONS ==="]
        data = filtered_data["persons"]
        if isinstance(data, str):
            section.append(f"  {data}")
        else:
            for p in data:
                line = f"  {p['name']} (ID: {p['person_id']}) — Role: {p['role']}"
                if p.get("major"):
                    line += f", Major: {p['major']}, Year: {p['year']}"
                if p.get("department"):
                    line += f", Dept: {p['department']}"
                if p.get("title"):
                    line += f", Title: {p['title']}"
                line += f", Email: {p['email']}, SSN: {p['ssn']}"
                section.append(line)
        sections.append("\n".join(section))

    if "financial_information" in filtered_data:
        section = ["\n=== FINANCIAL INFORMATION ==="]
        data = filtered_data["financial_information"]
        note = filtered_data.get("financial_information_note")
        if isinstance(data, str):
            section.append(f"  {data}")
        else:
            if note:
                section.append(f"  Note: {note}")
            for f in data:
                if f.get("type") == "tuition":
                    section.append(
                        f"  {f['person_id']}: Tuition — "
                        f"Due: ${f['amount_due']:,}, Paid: ${f['amount_paid']:,}, "
                        f"Balance: ${f['balance']:,}, "
                        f"Scholarship: {f['scholarship']}, Status: {f['status']}"
                    )
                elif f.get("type") == "salary":
                    section.append(
                        f"  {f['person_id']}: Salary — "
                        f"${f['annual_salary']:,}/year, {f['pay_frequency']}, "
                        f"Benefits: {f['benefits']}, Status: {f['status']}"
                    )
        sections.append("\n".join(section))

    if "grades" in filtered_data:
        section = ["\n=== GRADES ==="]
        data = filtered_data["grades"]
        if isinstance(data, str):
            section.append(f"  {data}")
        else:
            for g in data:
                section.append(
                    f"  Student {g['student_id']} in {g['class_id']}: "
                    f"Midterm {g['midterm']}, Final {g['final']}, "
                    f"Grade: {g['grade']}, Attendance: {g['attendance_rate'] * 100:.0f}%"
                )
        sections.append("\n".join(section))

    if "classes" in filtered_data:
        section = ["\n=== CLASSES ==="]
        data = filtered_data["classes"]
        if isinstance(data, str):
            section.append(f"  {data}")
        else:
            for c in data:
                students = ", ".join(c.get("enrolled_students", []))
                section.append(
                    f"  {c['class_id']} — {c['name']} | "
                    f"Teacher: {c.get('teacher_name', 'N/A')} | "
                    f"{c['schedule']} | Room: {c['room']} | "
                    f"Students: [{students}]"
                )
        sections.append("\n".join(section))

    return "\n".join(sections)
