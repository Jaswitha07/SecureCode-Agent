"""SecureCode Agent — FastAPI application.

Rate limiting via slowapi (200 req/min per IP by default).
AGENTS.md rule #6: no secrets are ever written to any log.
"""

from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.routers import auth, projects, tasks
from app.routers import audit as audit_router

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

app = FastAPI(
    title="SecureCode Agent",
    description="Policy-gated, human-supervised coding agent.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ─────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(tasks.router)
app.include_router(audit_router.router)


@app.get("/health")
async def health():
    """Liveness check."""
    return {"status": "ok"}
