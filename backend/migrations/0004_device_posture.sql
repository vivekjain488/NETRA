-- Phase 5: device posture.
--
-- The endpoint reports signals; the backend scores them. An endpoint that
-- computed its own trust score would be asserting its own trustworthiness,
-- which is exactly the claim NETRA must not accept (spec §43).

ALTER TABLE device_posture
    -- The individual contributions behind the score, so "why is this device
    -- 78?" is answerable from the record rather than recomputed from logs.
    ADD COLUMN factors JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Which scoring model produced this row. Weights are configurable, so a
    -- historical score is only interpretable alongside the model that made it.
    ADD COLUMN model_version TEXT NOT NULL DEFAULT 'posture-v1';

-- The SOC reads the latest posture per device constantly; this index serves
-- that lookup directly.
CREATE INDEX device_posture_latest_idx ON device_posture (device_id, collected_at DESC);
