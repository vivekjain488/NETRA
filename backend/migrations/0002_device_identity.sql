-- Phase 3: device identity.
--
-- Adds replay protection for device-signed requests and the indexes the
-- enrollment and heartbeat paths depend on.

-- Every device-signed request carries a unique nonce. Storing seen nonces with
-- a UNIQUE constraint makes replay rejection a database invariant rather than
-- something application code has to remember to check.
CREATE TABLE replay_nonces (
    nonce      TEXT        NOT NULL,
    device_id  UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, nonce)
);

-- Expired nonces are pruned on a schedule; the index keeps that cheap.
CREATE INDEX replay_nonces_seen_at_idx ON replay_nonces (seen_at);

-- Enrollment tokens are looked up by hash on every enrollment attempt.
-- token_hash is already UNIQUE, which serves that lookup.

-- Devices are listed by enrollment recency in the SOC console.
CREATE INDEX devices_enrolled_at_idx ON devices (enrolled_at DESC NULLS LAST);
