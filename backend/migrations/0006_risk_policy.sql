-- Phases 7-9: risk scoring, behavioural baselines, policy decisions.

-- ── Risk ────────────────────────────────────────────────────────────────────
-- A score is never stored without the reasons that produced it, so "why did
-- risk increase?" is answerable from the database rather than reconstructed
-- from logs (spec §20).
CREATE TABLE risk_scores (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id     UUID        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    user_id        UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id      UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    computed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    score          SMALLINT    NOT NULL,
    level          TEXT        NOT NULL,
    action         TEXT        NOT NULL,
    dimensions     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    model_version  TEXT        NOT NULL,
    trigger_event  TEXT,
    CONSTRAINT risk_scores_score_range CHECK (score BETWEEN 0 AND 100),
    CONSTRAINT risk_scores_level_known
        CHECK (level IN ('LOW', 'MEDIUM', 'ELEVATED', 'HIGH', 'CRITICAL'))
);
CREATE INDEX risk_scores_session_time_idx ON risk_scores (session_id, computed_at DESC);
CREATE INDEX risk_scores_user_time_idx ON risk_scores (user_id, computed_at DESC);
CREATE INDEX risk_scores_level_idx ON risk_scores (level, computed_at DESC);

CREATE TABLE risk_factors (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    risk_score_id UUID     NOT NULL REFERENCES risk_scores (id) ON DELETE CASCADE,
    code          TEXT     NOT NULL,
    label         TEXT     NOT NULL,
    dimension     TEXT     NOT NULL,
    contribution  SMALLINT NOT NULL,
    detail        TEXT
);
CREATE INDEX risk_factors_score_idx ON risk_factors (risk_score_id);
CREATE INDEX risk_factors_code_idx ON risk_factors (code);

-- ── Behavioural baseline ────────────────────────────────────────────────────
-- One profile per user, rebuilt from their own history. Baselines are personal:
-- a night-shift operator's normal is not an office worker's (spec §12).
CREATE TABLE behaviour_profiles (
    user_id            UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    window_days        SMALLINT    NOT NULL,
    observation_count  INTEGER     NOT NULL DEFAULT 0,
    -- 24 buckets of sign-in counts, indexed by hour in UTC.
    login_hours        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    known_devices      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    known_applications JSONB       NOT NULL DEFAULT '[]'::jsonb,
    known_networks     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Mean and standard deviation of events per session, for the z-score.
    access_rate_mean   DOUBLE PRECISION NOT NULL DEFAULT 0,
    access_rate_stddev DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- Whether there is enough history for the baseline to be meaningful.
    established        BOOLEAN     NOT NULL DEFAULT false
);

-- ── Policy ──────────────────────────────────────────────────────────────────
-- Policies are immutable versioned rows: a decision can always cite the exact
-- text that was in force when it was made (spec §25).
CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   TEXT        NOT NULL,
    version     INTEGER     NOT NULL,
    name        TEXT        NOT NULL,
    description TEXT,
    priority    SMALLINT    NOT NULL DEFAULT 100,
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    conditions  JSONB       NOT NULL,
    actions     JSONB       NOT NULL,
    -- What to do when the control plane cannot be reached (spec §29).
    fail_mode   TEXT        NOT NULL DEFAULT 'fail-safe',
    created_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version),
    CONSTRAINT policies_fail_mode_known
        CHECK (fail_mode IN ('fail-open', 'fail-closed', 'fail-safe'))
);
CREATE INDEX policies_active_idx ON policies (policy_id, version DESC) WHERE enabled;

CREATE TABLE policy_decisions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id     UUID        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    user_id        UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id      UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    risk_score_id  UUID        REFERENCES risk_scores (id) ON DELETE SET NULL,
    resource_id    UUID        REFERENCES resources (id) ON DELETE SET NULL,
    policy_id      TEXT,
    policy_version INTEGER,
    decision       TEXT        NOT NULL,
    reason         TEXT        NOT NULL,
    evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    latency_us     INTEGER     NOT NULL DEFAULT 0,
    incident_id    UUID,
    CONSTRAINT policy_decisions_known CHECK (decision IN
        ('ALLOW', 'ALLOW_MONITOR', 'VERIFY', 'STEP_UP_MFA', 'RESTRICT', 'ISOLATE', 'DENY'))
);
CREATE INDEX policy_decisions_session_idx ON policy_decisions (session_id, evaluated_at DESC);
CREATE INDEX policy_decisions_time_idx ON policy_decisions (evaluated_at DESC);

-- ── Incidents ───────────────────────────────────────────────────────────────
-- Correlated escalations, so a SOC sees one incident rather than five
-- disconnected alerts (spec §27).
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_key    TEXT        NOT NULL UNIQUE,
    title           TEXT        NOT NULL,
    summary         TEXT,
    severity        TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'OPEN',
    user_id         UUID        REFERENCES users (id) ON DELETE SET NULL,
    device_id       UUID        REFERENCES devices (id) ON DELETE SET NULL,
    session_id      UUID        REFERENCES sessions (id) ON DELETE SET NULL,
    peak_risk       SMALLINT    NOT NULL DEFAULT 0,
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ,
    assigned_to     UUID        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT incidents_severity_known
        CHECK (severity IN ('LOW', 'MEDIUM', 'ELEVATED', 'HIGH', 'CRITICAL')),
    CONSTRAINT incidents_status_known
        CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'))
);
CREATE INDEX incidents_status_idx ON incidents (status, opened_at DESC);
CREATE INDEX incidents_user_idx ON incidents (user_id, opened_at DESC);

CREATE TABLE incident_events (
    incident_id UUID    NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    event_id    UUID    NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE incident_notes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID        NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    author_id   UUID        REFERENCES users (id) ON DELETE SET NULL,
    body        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX incident_notes_incident_idx ON incident_notes (incident_id, created_at);

ALTER TABLE policy_decisions
    ADD CONSTRAINT policy_decisions_incident_fk
    FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE SET NULL;
