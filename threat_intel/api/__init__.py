"""API routes package."""

from threat_intel.api.admin import router as admin_router
from threat_intel.api.ioc import router as ioc_router
from threat_intel.api.stats import router as stats_router

__all__ = ["admin_router", "ioc_router", "stats_router"]
