-- Phase 6: telemetry ingest.
--
-- Agents batch events locally and retry after an outage, so the same event can
-- arrive more than once. Deduplication is a database invariant rather than
-- application logic that could be forgotten on a new code path.

ALTER TABLE events
    -- The identifier the agent assigned before transmission. Unique per device,
    -- so a replayed batch inserts nothing rather than duplicating history.
    ADD COLUMN agent_event_id TEXT,
    -- Groups events that arrived together, so an operator can see which batch
    -- an event came from when diagnosing an ingest problem.
    ADD COLUMN batch_id UUID;

CREATE UNIQUE INDEX events_device_agent_event_idx
    ON events (device_id, agent_event_id)
    WHERE agent_event_id IS NOT NULL;

CREATE INDEX events_batch_idx ON events (batch_id) WHERE batch_id IS NOT NULL;

-- The SOC filters the event stream by severity far more often than it reads
-- everything, so that ordering deserves its own index.
CREATE INDEX events_severity_time_idx ON events (severity, occurred_at DESC);
