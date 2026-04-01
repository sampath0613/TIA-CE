"""FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from threat_intel import setup_logging
from threat_intel.api.admin import router as admin_router
from threat_intel.api.graph import router as graph_router
from threat_intel.api.ioc import router as ioc_router
from threat_intel.api.stats import router as stats_router
from threat_intel.config import get_settings
from threat_intel.db.database import AsyncSessionLocal, check_database_connection
from threat_intel.db.seed import seed_source_configs
from threat_intel.feeds.registry import FEED_REGISTRY
from threat_intel.pipeline.scheduler import create_scheduler

settings = get_settings()
setup_logging(settings.log_level)
logger = logging.getLogger(__name__)
project_root = Path(__file__).resolve().parents[1]
templates = Jinja2Templates(directory=str(project_root / "dashboard" / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App startup/shutdown lifecycle hook."""
    database_ok = await check_database_connection()
    scheduler: AsyncIOScheduler | None = None
    if database_ok:
        async with AsyncSessionLocal() as db:
            await seed_source_configs(db, settings)
            await db.commit()
    else:
        logger.warning("startup_seed_skipped database_unreachable=true")

    if settings.enable_scheduler and database_ok:
        scheduler = create_scheduler(settings)
        scheduler.start()
        app.state.scheduler = scheduler
        logger.info("scheduler_started job_count=%s", len(scheduler.get_jobs()))

    if not database_ok:
        logger.warning("startup_db_check_failed")
    else:
        logger.info("startup_db_check_ok")

    yield

    active_scheduler = getattr(app.state, "scheduler", scheduler)
    if active_scheduler is not None:
        active_scheduler.shutdown(wait=False)
        logger.info("scheduler_stopped")


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.mount(
    "/static",
    StaticFiles(directory=str(project_root / "dashboard" / "static")),
    name="static",
)


@app.middleware("http")
async def api_key_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Protect API endpoints with a static API key header."""
    open_paths = {"/health", "/docs", "/redoc", "/openapi.json"}
    if (
        not settings.enable_api_key_auth
        or request.url.path in open_paths
        or request.url.path.startswith("/dashboard")
        or request.url.path.startswith("/static")
    ):
        return await call_next(request)

    provided_key = request.headers.get("X-API-Key")
    if provided_key != settings.threat_intel_api_key:
        return JSONResponse(status_code=401, content={"detail": "Invalid API key"})

    return await call_next(request)


@app.get("/health")
async def health() -> dict[str, object]:
    """Return API and DB health status."""
    database_connected = await check_database_connection()

    async with httpx.AsyncClient() as client:
        async def _check_feed(source_id: str) -> dict[str, object]:
            adapter_cls = FEED_REGISTRY[source_id]
            adapter = adapter_cls(settings=settings, http_client=client)
            try:
                reachable = await adapter.health_check()
            except Exception:
                reachable = False
            return {
                "source_id": source_id,
                "display_name": adapter_cls.display_name,
                "reachable": reachable,
            }

        feed_checks = await asyncio.gather(*[_check_feed(source_id) for source_id in FEED_REGISTRY])

    overall_status = "ok" if database_connected and all(
        bool(feed["reachable"]) for feed in feed_checks
    ) else "degraded"

    return {
        "status": overall_status,
        "database_connected": database_connected,
        "feeds": feed_checks,
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_overview(request: Request) -> HTMLResponse:
    """Render dashboard overview page."""
    return templates.TemplateResponse(
        "overview.html",
        {
            "request": request,
            "refresh_seconds": settings.dashboard_auto_refresh_seconds,
            "api_key": settings.threat_intel_api_key,
        },
    )


@app.get("/dashboard/ioc/{value:path}", response_class=HTMLResponse)
async def dashboard_ioc_detail(request: Request, value: str) -> HTMLResponse:
    """Render IOC detail dashboard page."""
    return templates.TemplateResponse(
        "ioc_detail.html",
        {
            "request": request,
            "ioc_value": value,
            "api_key": settings.threat_intel_api_key,
        },
    )


app.include_router(ioc_router)
app.include_router(stats_router)
app.include_router(admin_router)
app.include_router(graph_router)
