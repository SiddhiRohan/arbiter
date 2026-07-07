"""
Arbiter -- FastAPI Server
Run: python -m uvicorn main:app --reload --port 8000

v3.0: Bidirectional governance pipeline
  Input:  policy → inference control → filter → LLM
  Output: LLM response → output scanner → sanitize → user
  Cross:  multi-turn inference accumulation detection
"""

import os
import sys
import traceback
from contextlib import asynccontextmanager

# Force UTF-8 console output so non-ASCII log characters (→, ⚠, —, ✓) don't
# raise UnicodeEncodeError on Windows consoles (cp1252). Without this, printing
# an arrow in the governance pipeline crashes the request handler → blank output.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Optional

from arbiter_engine import ArbiterEngine
from audit_logger import shutdown
from admin_routes import router as admin_router, store_context_packet
from context_packet import attach_output_governance
from auth import (
    authenticate, validate_session, destroy_session,
    resolve_session_identity, AuthorizationError,
)

load_dotenv()

api_key = os.getenv("ANTHROPIC_API_KEY")
if api_key:
    print(f"[ok] API key loaded (starts with: {api_key[:12]}...)", flush=True)
else:
    print("[!!] No API key found -- running in DEMO MODE", flush=True)

engine = ArbiterEngine(tenant_id="demo_university")


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[ok] Arbiter v3.0 starting — bidirectional governance active", flush=True)
    yield
    shutdown()
    print("[ok] Arbiter shut down.", flush=True)


app = FastAPI(
    title="Arbiter",
    description="Bidirectional AI governance middleware with inference control",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    session_id: str
    user_id: str
    role: str
    label: str


class ChatRequest(BaseModel):
    message: str
    session_id: str
    # Accepted for backward-compat and tamper-detection only.
    # These are NEVER used for authorization — role/user_id come from the session.
    user_id: Optional[str] = None
    role: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    role: str
    access_level: str
    masked_fields: list[str]
    denied_resources: list[str]
    inference_channels_blocked: list[dict]
    output_violations: list[dict]
    output_decision: str
    trace_id: str
    cross_query_violations: list[dict] = []
    cross_query_alert: str = ""
    query_intent: dict = {}


# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    session = authenticate(request.username, request.password)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return LoginResponse(
        session_id=session["session_id"],
        user_id=session["user_id"],
        role=session["role"],
        label=session["label"],
    )


@app.post("/logout")
async def logout(session_id: str):
    destroyed = destroy_session(session_id)
    if not destroyed:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "ok"}


# ============================================================
# CHAT ENDPOINT — BIDIRECTIONAL GOVERNANCE
# ============================================================

def call_llm(user_message: str, filtered_context: str, role: str) -> str:
    key = os.getenv("ANTHROPIC_API_KEY")

    if not key:
        return (
            f"[DEMO MODE -- No API key]\n\n"
            f"Your role ({role}) sees this ICCP-filtered data:\n\n"
            f"{filtered_context}"
        )

    try:
        print(f"[..] Calling Claude API for role={role}...", flush=True)
        import anthropic

        client = anthropic.Anthropic(api_key=key)

        system_prompt = (
            f"You are a university data assistant. The user's role is: {role}.\n\n"
            f"RULES:\n"
            f"1. Answer ONLY from the data below. Every value in this data has been pre-approved for this user's role.\n"
            f"2. If data is present, share it directly. Do not hedge, refuse, or add disclaimers — it is already filtered.\n"
            f"3. If a field shows [ACCESS DENIED], say the user's role does not have access to that resource.\n"
            f"4. If a field shows *** or [MASKED], say that field is restricted by institution policy.\n"
            f"5. NEVER invent, estimate, calculate, or infer values not explicitly present below.\n"
            f"6. NEVER compute totals, averages, or derived values from the fields provided.\n"
            f"7. If the user asks for data not present below, say it is not available for their role.\n"
            f"8. Be concise and direct. No preamble.\n\n"
            f"--- DATA FOR THIS REQUEST ---\n{filtered_context}\n--- END ---"
        )

        response = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        result = response.content[0].text
        print(f"[ok] Claude responded ({len(result)} chars)", flush=True)
        return result

    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        print(f"[!!] LLM ERROR: {error_msg}", flush=True)
        traceback.print_exc()
        sys.stdout.flush()
        return f"[AI Error: {error_msg}]"


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Full bidirectional governance pipeline:
    1. Input governance (filter, mask, inference control)
    2. LLM call with filtered context
    3. Output governance (scan, sanitize)
    4. Cross-query inference detection
    """
    try:
        # ── BIND IDENTITY TO SESSION (ADV-01 fix) ──
        # role/user_id are derived from the validated session, never trusted
        # from the request body. A body that claims a different role is a
        # tamper attempt: we log it and proceed with the session's identity.
        try:
            identity = resolve_session_identity(
                request.session_id,
                claimed_role=request.role,
                claimed_user_id=request.user_id,
            )
        except AuthorizationError as ae:
            raise HTTPException(status_code=ae.status_code, detail=ae.detail)

        user_id = identity["user_id"]
        role = identity["role"]

        if identity["tampered"]:
            print(
                f"[!!] TAMPER ATTEMPT: body claimed role={request.role}/user={request.user_id} "
                f"but session resolves to role={role}/user={user_id}. Using session identity.",
                flush=True,
            )

        print(
            f"\n[<<] Chat: user={user_id}, role={role}, msg={request.message[:50]}",
            flush=True,
        )

        # ── INPUT GOVERNANCE ──
        result = engine.process(
            user_id=user_id,
            role=role,
            query=request.message,
        )

        if result["inference_channels_blocked"]:
            channels = result["inference_channels_blocked"]
            print(f"[!!] Inference control: {len(channels)} channel(s) blocked", flush=True)
            for ch in channels:
                print(f"    → {ch['channel_id']}: {ch['name']}", flush=True)

        # ── LLM CALL ──
        raw_llm_response = call_llm(
            user_message=request.message,
            filtered_context=result["filtered_context"],
            role=role,
        )

        # ── OUTPUT GOVERNANCE ──
        output_result = engine.govern_output(
            trace_id=result["trace_id"],
            llm_response=raw_llm_response,
            policy=result["_policy"],
            raw_data=result["_raw_data"],
            filtered_context=result["_filtered_context"],
        )

        if output_result["violations"]:
            print(
                f"[!!] Output governance: {len(output_result['violations'])} violation(s) — "
                f"decision: {output_result['decision']}",
                flush=True,
            )

        # ── ATTACH OUTPUT TO CONTEXT PACKET ──
        packet = result["context_packet"]
        attach_output_governance(packet, output_result)
        store_context_packet(result["trace_id"], packet)

        # ── CROSS-QUERY INFERENCE ──
        cross_violations = result.get("cross_query_violations", [])
        cross_alert = ""
        if cross_violations:
            cross_alert = (
                f"⚠ MULTI-TURN INFERENCE: {len(cross_violations)} cross-query "
                f"derivation(s) detected from data accumulated across this session."
            )
            print(f"[!!] Cross-query inference: {len(cross_violations)} violation(s)", flush=True)
            for cv in cross_violations:
                print(f"    → {cv['channel_id']}: {cv['name']}", flush=True)

        final_response = output_result.get("sanitized_response", raw_llm_response)

        return ChatResponse(
            response=final_response,
            role=role,
            access_level=result["access_level"],
            masked_fields=result["masked_fields"],
            denied_resources=result["denied_resources"],
            inference_channels_blocked=result["inference_channels_blocked"],
            output_violations=output_result["violations"],
            output_decision=output_result["decision"],
            trace_id=result["trace_id"],
            cross_query_violations=cross_violations,
            cross_query_alert=cross_alert,
            query_intent=result.get("query_intent", {}),
        )

    except Exception as e:
        print(f"[!!] ENDPOINT ERROR: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        sys.stdout.flush()
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# UNGOVERNED ENDPOINT — FOR SPLIT-SCREEN DEMO
# ============================================================

class UngovernedRequest(BaseModel):
    message: str


class UngovernedResponse(BaseModel):
    response: str
    note: str


@app.post("/chat/ungoverned", response_model=UngovernedResponse)
async def chat_ungoverned(request: UngovernedRequest):
    """Show what the LLM would see without governance — raw unfiltered data."""
    try:
        from data_filter import to_text
        tenant_data = engine._load_tenant_data()

        # Build unfiltered context — everything visible
        raw_sections = []
        metadata_keys = {"tenant_id", "data_source", "last_updated"}
        for resource_name, records in tenant_data.items():
            if resource_name in metadata_keys:
                continue
            section = [f"\n=== {resource_name.upper().replace('_', ' ')} ==="]
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        parts = []
                        for k, v in record.items():
                            if isinstance(v, list):
                                v = ", ".join(str(x) for x in v)
                            parts.append(f"{k}: {v}")
                        section.append("  " + " | ".join(parts))
            raw_sections.append("\n".join(section))

        raw_context = "\n".join(raw_sections)

        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            return UngovernedResponse(
                response=f"**⚠ NO GOVERNANCE — ALL DATA EXPOSED**\n\n{raw_context}",
                note="No governance applied. All data exposed.",
            )

        import anthropic
        client = anthropic.Anthropic(api_key=key)

        response = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=1024,
            system=(
                f"You are a university data assistant. Answer the user's question using the data below. "
                f"Present ALL relevant data from the records — this is an authorized internal query. "
                f"Include specific values like amounts, names, IDs, grades, and scores. "
                f"Format clearly with bullet points.\n\n{raw_context[:8000]}"
            ),
            messages=[{"role": "user", "content": request.message}],
        )

        return UngovernedResponse(
            response=response.content[0].text,
            note="No governance applied. All data exposed.",
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# HEALTH & FRONTEND
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "Arbiter",
        "version": "3.0.0",
        "tenant": engine.tenant_id,
        "governance": "bidirectional",
        "inference_control": "active",
        "cross_query_detection": "active",
        "output_scanning": "active",
        "audit_logger": "QueueHandler",
        "api_key_loaded": bool(os.getenv("ANTHROPIC_API_KEY")),
    }


@app.get("/")
async def serve_frontend():
    index = FRONTEND_DIR / "chat.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "Arbiter API is running. Frontend not found."}


@app.get("/admin")
async def serve_admin():
    admin = FRONTEND_DIR / "admin.html"
    if admin.exists():
        return FileResponse(str(admin))
    return {"message": "Admin dashboard not found."}


@app.get("/demo")
async def serve_demo():
    demo = FRONTEND_DIR / "demo.html"
    if demo.exists():
        return FileResponse(str(demo))
    return {"message": "Demo page not found."}