"""FastAPI application: JSON over HTTPS at /v1, authenticated with Bearer API keys."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .config import settings
from .db import init_db
from .errors import ApiError, api_error_handler
from .routers import accounts, domains, messages, plans, webhooks

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        from . import storage

        storage.ensure_bucket()
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("startup").warning(
            "bucket not available yet (%s); run `python -m scripts.storage_init` once MinIO is up", exc
        )
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Self-hosted mail platform: domains + DNS, sending, receiving, "
        "storage in S3-compatible object storage. Plans are limits only.",
        lifespan=lifespan,
    )
    app.add_exception_handler(ApiError, api_error_handler)

    app.include_router(plans.router)
    app.include_router(accounts.router)
    app.include_router(domains.router)
    app.include_router(messages.router)
    app.include_router(webhooks.router)

    @app.get("/", include_in_schema=False)
    def root():
        return {"service": settings.app_name, "docs": "/docs", "api": "/v1"}

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        ok = {"db": False, "redis": False}
        try:
            from sqlalchemy import text

            from .db import engine

            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            ok["db"] = True
        except Exception:  # noqa: BLE001
            pass
        try:
            from .deps import get_redis

            get_redis().ping()
            ok["redis"] = True
        except Exception:  # noqa: BLE001
            pass
        return JSONResponse({"status": "ok" if all(ok.values()) else "degraded", **ok})

    return app


app = create_app()
