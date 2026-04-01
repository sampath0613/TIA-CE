"""Database engine and session management."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from threat_intel.config import Settings, get_settings


class Base(DeclarativeBase):
    """Base declarative class for ORM models."""


def create_engine_from_settings(settings: Settings | None = None) -> AsyncEngine:
    """Create an async SQLAlchemy engine.

    Args:
        settings: Optional settings override.

    Returns:
        Configured AsyncEngine.
    """
    active_settings = settings or get_settings()
    return create_async_engine(
        active_settings.sqlalchemy_async_database_uri,
        echo=active_settings.database_echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine: AsyncEngine = create_engine_from_settings()
AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Yield a database session for dependency injection."""
    async with AsyncSessionLocal() as session:
        yield session


async def check_database_connection() -> bool:
    """Check database connectivity with a lightweight query."""
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
