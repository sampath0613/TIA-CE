"""Shared pytest fixtures for async DB and API testing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from threat_intel.config import get_settings
from threat_intel.db.database import Base
from threat_intel.models.db import SourceConfig


@pytest.fixture(autouse=True, scope="session")
def configure_test_environment() -> None:
    """Configure stable environment defaults for test execution."""
    os.environ["OTX_API_KEY"] = "test-otx-key"
    get_settings.cache_clear()


@pytest_asyncio.fixture(scope="session")
async def test_engine(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[AsyncEngine]:
    """Create an async SQLite engine for unit tests."""
    db_dir = tmp_path_factory.mktemp("db")
    db_path = db_dir / "unit_tests.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(test_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Return async session factory bound to test engine."""
    return async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture
async def db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Provide an isolated async DB session per test."""
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(autouse=True)
async def seed_source_configs(db_session: AsyncSession) -> None:
    """Seed source configurations before each test."""
    for table in reversed(Base.metadata.sorted_tables):
        await db_session.execute(table.delete())
    await db_session.commit()

    source_rows = [
        {
            "id": "alienvault_otx",
            "display_name": "AlienVault OTX",
            "source_weight": 0.65,
        },
        {
            "id": "urlhaus",
            "display_name": "URLhaus",
            "source_weight": 0.80,
        },
        {
            "id": "feodo_tracker",
            "display_name": "Feodo Tracker",
            "source_weight": 0.90,
        },
        {
            "id": "emerging_threats",
            "display_name": "Emerging Threats",
            "source_weight": 0.70,
        },
    ]

    for row in source_rows:
        db_session.add(
            SourceConfig(
                id=row["id"],
                display_name=row["display_name"],
                source_weight=row["source_weight"],
                lambda_ip=0.015,
                lambda_domain=0.008,
                lambda_hash=0.002,
                lambda_url=0.020,
                last_ingestion_at=datetime.now(UTC),
                last_ingestion_count=0,
                last_ingestion_error=None,
                cumulative_fp_count=0,
                cumulative_tp_count=0,
            )
        )
    await db_session.commit()


@pytest_asyncio.fixture
async def api_client() -> AsyncIterator[AsyncClient]:
    """Provide async HTTP client bound to ASGI app transport."""
    app = FastAPI()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
