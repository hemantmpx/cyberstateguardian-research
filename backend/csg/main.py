from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from csg.api.routes import router as api_router
from csg.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Source-independent security state monitoring and deterministic reconciliation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": "csg-api",
        "environment": settings.app_env,
        "database_configured": bool(settings.database_url),
        "time": datetime.now(UTC).isoformat(),
    }


app.include_router(api_router)
