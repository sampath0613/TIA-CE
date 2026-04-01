"""Feed adapter registry."""

from __future__ import annotations

from threat_intel.feeds.alienvault_otx import AlienVaultOTXFeed
from threat_intel.feeds.base import BaseFeedAdapter
from threat_intel.feeds.emerging_threats import EmergingThreatsFeed
from threat_intel.feeds.feodo_tracker import FeodoTrackerFeed
from threat_intel.feeds.urlhaus import URLHausFeed

FEED_REGISTRY: dict[str, type[BaseFeedAdapter]] = {
    AlienVaultOTXFeed.source_id: AlienVaultOTXFeed,
    FeodoTrackerFeed.source_id: FeodoTrackerFeed,
    EmergingThreatsFeed.source_id: EmergingThreatsFeed,
    URLHausFeed.source_id: URLHausFeed,
}
