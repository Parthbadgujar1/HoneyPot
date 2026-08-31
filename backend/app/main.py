"""SentinelTrap - FastAPI application entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

    # seed an admin user so login works out of the box
    from app.models.models import User
    from app.security.auth import hash_password

    db = SessionLocal()
    if not db.query(User).filter(User.username == "admin").first():
        db.add(
            User(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password("admin123"),
                role="ADMIN",
            )
        )
        db.add(
            User(
                username="analyst",
                email="analyst@example.com",
                hashed_password=hash_password("analyst123"),
                role="ANALYST",
            )
        )
        db.add(
            User(
                username="viewer",
                email="viewer@example.com",
                hashed_password=hash_password("viewer123"),
                role="VIEWER",
            )
        )
        db.commit()
    db.close()

    app.state.adapter = adapter
    app.state.collector = collector
    app.state.db_factory = SessionLocal

    db = SessionLocal()
    app.state.deception_engine = DeceptionEngine(db, adapter=adapter)
    db.close()

    collector.start()
    logger.info("SentinelTrap started")
    yield
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
    allow_methods=["*"],
    allow_headers=["*"],
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
        db.execute("SELECT 1")
        db.close()
        return {"status": "ready", "db": "ok"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "not_ready", "db": str(e)})


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
