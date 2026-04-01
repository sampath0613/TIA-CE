# Adding a Feed (SOP)

Step 1: Create `threat_intel/feeds/your_feed.py`

Step 2: Implement `BaseFeedAdapter` with `source_id`, `display_name`, and `default_weight` class variables.

Step 3: Implement `fetch()`:
- Handle authentication, pagination, and transient error retries.
- Parse source wire format and return `list[NormalizedIOC]`.
- Raise `FeedFetchError` for unrecoverable failures.

Step 4: Register adapter in `FEED_REGISTRY` in `threat_intel/feeds/registry.py`.

Step 5: Add source row in DB seeding logic (`threat_intel/db/seed.py`) with default weight and lambda values.

Step 6: Add scheduler interval environment variable in `.env.example` and update source interval mapping in `threat_intel/pipeline/scheduler.py`.

Step 7: Add fixture payload file under `tests/fixtures/` and implement adapter tests in `tests/unit/test_feeds.py`.

Step 8: Add required API keys or configuration variables to `.env.example`.
