"""SentinelTrap - FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import SessionLocal, engine
from app.core.logging import get_logger
from app.deception.engine import DeceptionEngine
from app.honeypot.factory import default_adapter
from app.models import models  # noqa: F401  (register tables)
from app.services.collector import TelemetryCollector

settings = get_settings()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # create tables
    models.Base.metadata.create_all(bind=engine)
    logger.info("Database tables ensured")

    adapter = default_adapter()
    collector = TelemetryCollector(SessionLocal, adapter)

    # Seed demo users ONLY in debug/dev so default credentials are never
    # created in production.
    db = SessionLocal()
    try:
        if settings.DEBUG:
            from app.models.models import User
            from app.security.auth import hash_password

            seeded = [
                ("admin", "admin@example.com", "admin123", "ADMIN"),
                ("analyst", "analyst@example.com", "analyst123", "ANALYST"),
                ("viewer", "viewer@example.com", "viewer123", "VIEWER"),
            ]
            for username, email, password, role in seeded:
                if not db.query(User).filter(User.username == username).first():
                    db.add(
                        User(
                            username=username,
                            email=email,
                            hashed_password=hash_password(password),
                            role=role,
                        )
                    )
            db.commit()
    finally:
        db.close()

    app.state.adapter = adapter
    app.state.collector = collector
    app.state.db_factory = SessionLocal

    # Keep a dedicated session open for the lifetime of the process; the
    # engine retains and reuses it across calls. Closed on shutdown below.
    engine_db = SessionLocal()
    app.state.deception_engine = DeceptionEngine(engine_db, adapter=adapter)
    app.state.deception_engine_db = engine_db

    collector.start()
    logger.info("SentinelTrap started")
    yield
    db = getattr(app.state, "deception_engine_db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass
    collector.stop()
    logger.info("SentinelTrap stopped")


app = FastAPI(
    title="SentinelTrap - Adaptive AI Cyber Deception and Threat Intelligence Platform",
    version=settings.APP_VERSION,
    description=(
        "AICD-TIP / SentinelTrap: isolated honeypot + behavioural ML + anomaly "
        "detection + sequence prediction + risk engine + adaptive deception + SOC dashboard."
    ),
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, exc)
    # Do not leak stack traces in production responses
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentineltrap-api"}


@app.get("/ready")
def ready():
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
        return {"status": "ready", "db": "ok"}
    except Exception:
        # do not leak DB connection details / secrets to the caller
        return JSONResponse(
            status_code=503, content={"status": "not_ready", "db": "unavailable"}
        )


# Routers
from app.api import (  # noqa: E402
    analytics,
    anomalies,
    audit,
    auth,
    behaviours,
    dashboard,
    deception,
    events,
    honeypot,
    models as models_api,
    risk,
    sessions,
    system as system_api,
    ws,
)

app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_PREFIX)
app.include_router(events.router, prefix=settings.API_PREFIX)
app.include_router(sessions.router, prefix=settings.API_PREFIX)
app.include_router(anomalies.router, prefix=settings.API_PREFIX)
app.include_router(behaviours.router, prefix=settings.API_PREFIX)
app.include_router(risk.router, prefix=settings.API_PREFIX)
app.include_router(deception.router, prefix=settings.API_PREFIX)
app.include_router(honeypot.router, prefix=settings.API_PREFIX)
app.include_router(models_api.router, prefix=settings.API_PREFIX)
app.include_router(analytics.router, prefix=settings.API_PREFIX)
app.include_router(audit.router, prefix=settings.API_PREFIX)
app.include_router(system_api.router, prefix=settings.API_PREFIX)
app.include_router(ws.router)  # websocket has no api prefix
