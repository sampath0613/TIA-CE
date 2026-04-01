"""Ingestion pipeline package."""

from threat_intel.pipeline.deduplicator import upsert_ioc
from threat_intel.pipeline.ingestor import IngestionSummary, run_all_feeds, run_ingestion
from threat_intel.pipeline.scheduler import create_scheduler

__all__ = [
	"IngestionSummary",
	"create_scheduler",
	"run_all_feeds",
	"run_ingestion",
	"upsert_ioc",
]
