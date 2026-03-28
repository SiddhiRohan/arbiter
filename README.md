# Arbiter

**AI governance middleware that controls what data a model is allowed to see.**

Arbiter sits between users and LLMs, enforcing role-based access control, PII masking, and full audit logging before any data reaches the AI. Built for regulated industries where unauthorized data access isn't just a bug — it's a compliance violation.

---

## The Problem

Organizations are deploying AI into sensitive workflows — student records, financial data, healthcare systems — but most AI tools have no concept of "who should see what." A teacher asking an AI about student grades and a student asking the same question get the same answer. That's a FERPA violation waiting to happen.

Arbiter fixes this by enforcing access control at the middleware layer, before the LLM ever sees the data.

## How It Works

```
  User Request (role + query)
         |
         v
  +-----------------+
  |   Auth Layer    |   Verify identity, create session
  +-----------------+
         |
         v
  +-----------------+
  |  Policy Engine  |   Load rules from JSON config
  |                 |   Evaluate: allow / deny / mask
  +-----------------+
         |
    +----+----+
    |         |
    v         v
+--------+ +----------+
| Filter | | Context  |
| Data   | | Packet   |
|        | | (CCP 2.0)|
+--------+ +----------+
    |         |
    +----+----+
         |
         v
  +-----------------+
  |   LLM Call      |   Model sees ONLY authorized data
  +-----------------+
         |
         v
  +-----------------+
  |  Audit Logger   |   Trace ID, decision, PII-scrubbed
  +-----------------+
         |
         v
  Response to User
```

## What Arbiter Enforces

| Rule | Example |
|---|---|
| **Role-based resource access** | Students cannot access grade records |
| **Record scoping** | Teachers see only their own salary, not others' |
| **Field masking** | SSN is always masked to `***-**-****` for every role |
| **Prohibited combinations** | Student + financial_information_others = DENY |
| **Full audit trail** | Every request logged with trace ID, decision, and explanation |
| **Context Packets** | Every LLM call wrapped in a CCP v2.0 governance record |

## Demo: Three Roles, Same System, Different Data

**Admin** asks "Show me all financial records":
```
Access: ALLOW_FULL
Sees: All 4 tables — persons, financials, grades, classes
Masked: SSN -> ***-**-****
```

**Teacher** asks "What is my salary?":
```
Access: ALLOW_PARTIAL
Sees: Persons, grades, classes, own salary only
Denied: Other employees' salaries, student financial records
Masked: SSN -> ***-**-****
```

**Student** asks "Can I see grade records?":
```
Access: ALLOW_PARTIAL
Sees: Persons, classes, own tuition balance
Denied: All grade records, other students' financial data
Masked: SSN -> ***-**-****
```

The AI responds differently to each role — not because it's prompted to, but because it literally cannot see the unauthorized data.

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/SiddhiRohan/arbiter.git
cd arbiter/server
pip install -r requirements.txt
```

### 2. Run the tests

```bash
python test_engine.py    # Core engine tests (3 roles)
python test_api.py       # Full API tests (12 endpoints)
```

### 3. Start the server

```bash
python -m uvicorn main:app --reload --port 8000
```

### 4. Open the UI

- **Chat UI**: [http://localhost:8000](http://localhost:8000) — login with `admin/admin`, `teacher/teacher`, or `student/student`
- **Admin Dashboard**: [http://localhost:8000/admin](http://localhost:8000/admin) — manage roles, view audit logs, inspect context packets
- **API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs) — interactive Swagger documentation

### 5. (Optional) Enable live AI responses

Create `server/.env`:
```
ANTHROPIC_API_KEY=your-key-here
```

Without an API key, Arbiter runs in demo mode — the ICCP pipeline still enforces access control, it just returns the filtered data directly instead of passing it through Claude.

---

## Architecture

```
arbiter/
├── config/
│   ├── policies.json          # Institution rules, resource descriptors, model config
│   └── roles.json             # Dynamic role definitions (add any role via config)
├── data/
│   └── demo_university.json   # Pluggable data source (swap for any domain)
├── server/
│   ├── arbiter_engine.py      # Core ICCP orchestrator
│   ├── policy_engine.py       # JSON-driven policy evaluation + admin CRUD
│   ├── data_filter.py         # Role-based filtering, masking, scoping
│   ├── context_packet.py      # CCP v2.0 packet builder
│   ├── audit_logger.py        # QueueHandler pipeline, PII scrubbing
│   ├── auth.py                # Session management
│   ├── admin_routes.py        # 12 admin API endpoints
│   ├── main.py                # FastAPI app + LLM integration
│   ├── test_engine.py         # Engine integration tests
│   └── test_api.py            # API integration tests
├── frontend/
│   ├── chat.html              # Chat UI with login + access badges
│   └── admin.html             # Admin dashboard (5 tabs)
└── logs/
    └── audit_log.jsonl        # Auto-generated audit trail
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/login` | POST | Authenticate, create session |
| `/logout` | POST | Destroy session |
| `/chat` | POST | ICCP-governed chat with LLM |
| `/health` | GET | Server status |
| `/audit-log` | GET | All audit entries (PII-scrubbed) |
| `/audit-log/{trace_id}` | GET | Single audit entry |
| `/audit-log-file` | GET | Download .jsonl |
| `/context-packet/{trace_id}` | GET | CCP v2.0 packet |
| `/context-packets` | GET | List all packets |
| `/admin/roles` | GET/POST | List or create roles |
| `/admin/roles/{name}` | DELETE | Delete a role |
| `/admin/policies` | GET/PUT | View or update policies |
| `/admin/resources` | GET | List resource descriptors |
| `/admin/sessions` | GET | Active sessions |
| `/admin/config/export` | GET | Full config export |
| `/demo/roles` | GET | Available demo credentials |

## Key Design Decisions

**Policies are JSON, not code.** Every access rule lives in `config/policies.json` and `config/roles.json`. Adding a new role or changing a mask rule requires zero code changes. The admin dashboard writes directly to these files.

**CCP v2.0 Context Packets.** Every LLM invocation is wrapped in a packet documenting identity, authorized resources, denied resources, mask fields, TTL status, and a SHA-256 policy hash. This creates a complete, tamper-detectable governance record for every AI interaction.

**Non-blocking audit logging.** Uses Python's `QueueHandler` + `QueueListener` pattern. The chat endpoint doesn't wait for log writes. Three independent consumers (file, memory, console) can fail independently.

**Multi-tenant ready.** The engine takes a `tenant_id` parameter. Swap `demo_university` for `demo_hospital` or `demo_bank` — the policy engine and data filter are domain-agnostic.

**Demo mode fallback.** Without an API key, the full ICCP pipeline runs — filtering, masking, scoping, audit logging, context packets — but returns filtered data directly instead of calling Claude. The governance layer works independently of the LLM.

## Tech Stack

- **Backend**: Python, FastAPI, Uvicorn
- **AI Model**: Claude (Anthropic API), called only through ICCP
- **Audit**: Python `QueueHandler` + `QueueListener`, PII-scrubbed `.jsonl`
- **Config**: JSON-driven (no database required)
- **Frontend**: Vanilla HTML/CSS/JS (no build step)
- **Auth**: Session-based with TTL expiry

## What's Next

- Multi-tenant deployment with tenant-specific configs
- Support for multiple LLM providers (OpenAI, Gemini, open-source models)
- Database-backed policy storage (PostgreSQL)
- Webhook notifications for policy violations
- Data source connectors (LDAP, SIS APIs, FHIR for healthcare)
- Role hierarchy and delegation
- Policy simulation ("what would happen if this role asked this?")

---

## License

MIT

## Author

**Siddhi Rohan** — [LinkedIn](https://www.linkedin.com/in/siddhi-rohan/)
