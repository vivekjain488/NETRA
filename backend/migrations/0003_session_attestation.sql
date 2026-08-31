-- Phase 4: session attestation.
--
-- A NETRA session requires proof of two things at once: a valid user token and
-- possession of an enrolled device's private key. The nonce issued here is what
-- ties them together for one specific sign-in attempt.

CREATE TABLE session_nonces (
    nonce      TEXT        PRIMARY KEY,
    -- The nonce is issued to one user. A device attestation produced for one
    -- person's sign-in therefore cannot be presented for another's.
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    session_id UUID        REFERENCES sessions (id) ON DELETE SET NULL
);

CREATE INDEX session_nonces_expires_at_idx ON session_nonces (expires_at);
CREATE INDEX session_nonces_user_idx ON session_nonces (user_id, issued_at DESC);

-- How the session's device was proven. Recorded so an investigator can tell an
-- attested session from one established before attestation existed.
ALTER TABLE sessions
    ADD COLUMN attestation TEXT NOT NULL DEFAULT 'none',
    ADD CONSTRAINT sessions_attestation_known
        CHECK (attestation IN ('none', 'device-signature', 'mtls'));

-- Ending a session is a lookup by user across active sessions.
CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE status = 'ACTIVE';
