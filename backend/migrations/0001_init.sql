-- NETRA initial schema.
--
-- Migrations are forward-only. For a system whose audit log is evidentiary,
-- an automated "down" path that can drop history is a liability; corrections
-- are made by writing a new forward migration.
--
-- Later phases add: risk_scores, risk_factors, behaviour_profiles, policies,
-- policy_decisions, incidents, incident_events, incident_notes.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Enumerations ────────────────────────────────────────────────────────────
CREATE TYPE user_role AS ENUM ('USER', 'SECURITY_ANALYST', 'ADMIN', 'AUDITOR');

CREATE TYPE device_state AS ENUM ('PENDING', 'ACTIVE', 'REVOKED');

CREATE TYPE sensitivity AS ENUM ('PUBLIC', 'INTERNAL', 'SENSITIVE', 'CRITICAL');

CREATE TYPE session_status AS ENUM ('ACTIVE', 'RESTRICTED', 'ISOLATED', 'ENDED');

CREATE TYPE event_source AS ENUM ('AGENT', 'CLIENT', 'BACKEND', 'SIMULATOR');

CREATE TYPE event_severity AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- event_type is a TEXT column with a CHECK constraint rather than an enum:
-- spec §14 requires new event types to be addable without breaking existing
-- services, and altering a CHECK is cheaper than altering an enum in flight.

-- ── Users ───────────────────────────────────────────────────────────────────
-- NETRA never stores passwords (spec §6): authentication is delegated to the
-- identity provider and users are keyed by their OIDC subject.
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_subject  TEXT        NOT NULL UNIQUE,
    email             TEXT        NOT NULL,
    display_name      TEXT        NOT NULL,
    department        TEXT,
    role              user_role   NOT NULL DEFAULT 'USER',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email));

-- ── Devices ─────────────────────────────────────────────────────────────────
-- public_key holds the device's Ed25519 public key. The private key never
-- leaves the endpoint (spec §11), so there is no column for it by design.
CREATE TABLE devices (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_uid        TEXT         NOT NULL UNIQUE,
    hostname          TEXT         NOT NULL,
    os_name           TEXT         NOT NULL,
    os_version        TEXT         NOT NULL,
    agent_version     TEXT         NOT NULL,
    public_key        BYTEA        NOT NULL,
    key_algorithm     TEXT         NOT NULL DEFAULT 'ed25519',
    key_protection    TEXT         NOT NULL DEFAULT 'software',
    state             device_state NOT NULL DEFAULT 'PENDING',
    enrolled_at       TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revoked_reason    TEXT,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT devices_key_algorithm_supported CHECK (key_algorithm IN ('ed25519')),
    -- 'software' is the development identity; 'tpm' and 'windows-cert-store'
    -- are the hardware-backed forms (spec §11).
    CONSTRAINT devices_key_protection_known
        CHECK (key_protection IN ('software', 'tpm', 'windows-cert-store'))
);
CREATE INDEX devices_state_idx ON devices (state);
CREATE INDEX devices_last_heartbeat_idx ON devices (last_heartbeat_at DESC NULLS LAST);

-- Enrollment requires an administrator-issued, single-use token: anonymous
-- self-enrollment would let any host claim a device identity.
CREATE TABLE enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  BYTEA       NOT NULL UNIQUE,
    label       TEXT,
    created_by  UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    device_id   UUID        REFERENCES devices (id) ON DELETE SET NULL
);
CREATE INDEX enrollment_tokens_expires_idx ON enrollment_tokens (expires_at);

-- Posture is history, not a mutable field: an investigator needs the posture
-- as it was at the time of an event, not only the latest reading.
CREATE TABLE device_posture (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id    UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    trust_score  SMALLINT    NOT NULL,
    signals      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Posture reported by the agent is a claim, not proof; the backend records
    -- whether it could independently corroborate it (spec §38, §43).
    verified     BOOLEAN     NOT NULL DEFAULT false,
    CONSTRAINT device_posture_score_range CHECK (trust_score BETWEEN 0 AND 100)
);
CREATE INDEX device_posture_device_time_idx ON device_posture (device_id, collected_at DESC);

-- ── Applications and resources ──────────────────────────────────────────────
CREATE TABLE applications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    description TEXT,
    sensitivity sensitivity NOT NULL DEFAULT 'INTERNAL',
    launch_url  TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE resources (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID        NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    key            TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    description    TEXT,
    sensitivity    sensitivity NOT NULL DEFAULT 'INTERNAL',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (application_id, key)
);
CREATE INDEX resources_sensitivity_idx ON resources (sensitivity);

-- ── Sessions ────────────────────────────────────────────────────────────────
-- A session binds a verified user to a verified device (spec §26): both
-- columns are NOT NULL because NETRA has no concept of a user-only session.
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID           NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id       UUID           NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    status          session_status NOT NULL DEFAULT 'ACTIVE',
    auth_method     TEXT           NOT NULL DEFAULT 'oidc',
    source_ip       INET,
    network_context JSONB          NOT NULL DEFAULT '{}'::jsonb,
    current_risk    SMALLINT,
    current_level   TEXT,
    started_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ    NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    CONSTRAINT sessions_risk_range CHECK (current_risk IS NULL OR current_risk BETWEEN 0 AND 100)
);
CREATE INDEX sessions_user_started_idx ON sessions (user_id, started_at DESC);
CREATE INDEX sessions_device_started_idx ON sessions (device_id, started_at DESC);
CREATE INDEX sessions_active_idx ON sessions (last_seen_at DESC) WHERE status = 'ACTIVE';

-- ── Events ──────────────────────────────────────────────────────────────────
-- The normalized telemetry record (spec §14). occurred_at is endpoint time and
-- is therefore untrusted; received_at is authoritative server time.
CREATE TABLE events (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at    TIMESTAMPTZ    NOT NULL,
    received_at    TIMESTAMPTZ    NOT NULL DEFAULT now(),
    device_id      UUID           REFERENCES devices (id) ON DELETE SET NULL,
    user_id        UUID           REFERENCES users (id) ON DELETE SET NULL,
    session_id     UUID           REFERENCES sessions (id) ON DELETE SET NULL,
    event_type     TEXT           NOT NULL,
    application_id UUID           REFERENCES applications (id) ON DELETE SET NULL,
    resource_id    UUID           REFERENCES resources (id) ON DELETE SET NULL,
    severity       event_severity NOT NULL DEFAULT 'INFO',
    source         event_source   NOT NULL,
    metadata       JSONB          NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT events_type_known CHECK (event_type IN (
        'AUTH_LOGIN', 'AUTH_LOGOUT', 'DEVICE_ENROLLMENT', 'DEVICE_POSTURE',
        'APPLICATION_START', 'APPLICATION_ACCESS', 'RESOURCE_ACCESS',
        'PRIVILEGE_CHANGE', 'NETWORK_EVENT', 'SECURITY_EVENT',
        'POLICY_DECISION', 'RISK_UPDATE', 'SECURITY_ALERT'
    ))
);
CREATE INDEX events_user_time_idx ON events (user_id, occurred_at DESC);
CREATE INDEX events_device_time_idx ON events (device_id, occurred_at DESC);
CREATE INDEX events_session_time_idx ON events (session_id, occurred_at DESC);
CREATE INDEX events_type_time_idx ON events (event_type, occurred_at DESC);
CREATE INDEX events_received_idx ON events (received_at DESC);

-- ── Audit log ───────────────────────────────────────────────────────────────
-- Append-only and hash-chained: each row commits to the previous row's hash,
-- so removing or editing history is detectable (spec §33, §40).
CREATE TABLE audit_logs (
    seq         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type  TEXT        NOT NULL,
    actor_id    TEXT,
    action      TEXT        NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    result      TEXT        NOT NULL,
    request_id  TEXT,
    source_ip   INET,
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash   BYTEA,
    hash        BYTEA       NOT NULL,
    CONSTRAINT audit_logs_actor_type_known
        CHECK (actor_type IN ('USER', 'DEVICE', 'SYSTEM', 'SIMULATOR'))
);
CREATE INDEX audit_logs_at_idx ON audit_logs (at DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs (actor_type, actor_id, at DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action, at DESC);
