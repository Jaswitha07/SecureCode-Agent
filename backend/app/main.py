"""SecureCode Agent — FastAPI application."""

from fastapi import FastAPI

app = FastAPI(
    title="SecureCode Agent",
    description="Policy-gated, human-supervised coding agent.",
)


@app.get("/health")
async def health():
    """Liveness check."""
    return {"status": "ok"}
