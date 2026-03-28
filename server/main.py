"""
Arbiter -- FastAPI Server
Run: python -m uvicorn main:app --reload --port 8000
"""

import os
import sys
import traceback
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path

from arbiter_engine import ArbiterEngine
from audit_logger import shutdown
from admin_routes import router as admin_router, store_context_packet
from auth import authenticate, validate_session, destroy_session

load_dotenv()

api_key = os.getenv("ANTHROPIC_API_KEY")
if api_key:
    print(f"[ok] API key loaded (starts with: {api_key[:12]}...)", flush=True)
else:
    print("[!!] No API key found -- running in DEMO MODE", flush=True)

# Shared engine instance
engine = ArbiterEngine(tenant_id="demo_university")


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[ok] Arbiter starting...", flush=True)
    yield
    shutdown()
    print("[ok] Arbiter shut down.", flush=True)


app = FastAPI(
    title="Arbiter",
    description="ICCP-governed AI governance middleware",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount admin routes
app.include_router(admin_router)

# Serve frontend files
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
    user_id: str
    role: str
    message: str


class ChatResponse(BaseModel):
    response: str
    role: str
    access_level: str
    masked_fields: list[str]
    denied_resources: list[str]
    trace_id: str


# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate and create a session."""
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
    """Destroy a session."""
    destroyed = destroy_session(session_id)
    if not destroyed:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "ok"}


# ============================================================
# CHAT ENDPOINT
# ============================================================

def call_llm(user_message: str, filtered_context: str, role: str) -> str:
    """Call Claude API with ICCP-filtered context, or return demo response."""
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
            f"You are Arbiter AI, an ICCP-governed assistant. "
            f"Current user role: {role}. "
            f"ONLY use the data below. Do NOT make up information. "
            f"If data shows [ACCESS DENIED] or is masked (***), tell the user "
            f"their role cannot access it. Be helpful and concise.\n\n"
            f"--- ICCP-FILTERED DATA ---\n{filtered_context}\n--- END ---"
        )

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
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
    """Process a governed chat request through the ICCP pipeline."""
    try:
        print(
            f"\n[<<] Chat: user={request.user_id}, "
            f"role={request.role}, msg={request.message[:50]}",
            flush=True,
        )

        result = engine.process(
            user_id=request.user_id,
            role=request.role,
            query=request.message,
        )

        # Store context packet for retrieval via admin API
        store_context_packet(result["trace_id"], result["context_packet"])

        # Call LLM with filtered context
        ai_response = call_llm(
            user_message=request.message,
            filtered_context=result["filtered_context"],
            role=request.role,
        )

        return ChatResponse(
            response=ai_response,
            role=request.role,
            access_level=result["access_level"],
            masked_fields=result["masked_fields"],
            denied_resources=result["denied_resources"],
            trace_id=result["trace_id"],
        )

    except Exception as e:
        print(f"[!!] ENDPOINT ERROR: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        sys.stdout.flush()
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# HEALTH & FRONTEND
# ============================================================

@app.get("/health")
async def health():
    """Server health check."""
    return {
        "status": "ok",
        "service": "Arbiter",
        "version": "2.0.0",
        "tenant": engine.tenant_id,
        "iccp": "active",
        "audit_logger": "QueueHandler",
        "api_key_loaded": bool(os.getenv("ANTHROPIC_API_KEY")),
    }


@app.get("/")
async def serve_frontend():
    """Serve the chat frontend."""
    index = FRONTEND_DIR / "chat.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "Arbiter API is running. Frontend not found at /frontend/chat.html"}


@app.get("/admin")
async def serve_admin():
    """Serve the admin dashboard."""
    admin = FRONTEND_DIR / "admin.html"
    if admin.exists():
        return FileResponse(str(admin))
    return {"message": "Admin dashboard not found at /frontend/admin.html"}
