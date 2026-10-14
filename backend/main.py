"""
backend/main.py
AgentShield FastAPI application factory.

Startup lifecycle:
  1. Initialize PostgreSQL async engine.
  2. Initialize Redis connection pool.
  3. Register all API routers.
  4. Register domain exception handlers.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.exceptions import register_exception_handlers
from backend.storage.database import close_engine, init_engine
from backend.storage.redis_client import close_redis, init_redis

# ── API routers ───────────────────────────────────────────────────────────
from backend.api.health import router as health_router
from backend.api.agents import router as agents_router
from backend.api.gateway import router as gateway_router
from backend.api.executor import router as executor_router
from backend.api.approvals import router as approvals_router
from backend.api.audit import router as audit_router
from backend.api.observer import router as observer_router  # [GURURAJ] ground-truth snapshot


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    settings = get_settings()
    init_engine(settings.database_url)
    init_redis(settings.redis_url)
    yield
    await close_engine()
    await close_redis()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AgentShield",
        description=(
            "Zero-Trust Action Security for AI Agents. "
            "Every sensitive action is independently authorized before execution."
        ),
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS (frontend integration) ───────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception handlers ────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers ───────────────────────────────────────────────────────────
    app.include_router(health_router)
    app.include_router(agents_router)
    app.include_router(gateway_router)
    app.include_router(executor_router)
    app.include_router(approvals_router)
    app.include_router(audit_router)
    app.include_router(observer_router)   # [GURURAJ] read-only ground-truth snapshot

    return app


app = create_app()
