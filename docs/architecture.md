# Architecture

## Principle

NETRA treats **user**, **device**, **session** and **resource** as four separate
security objects. A decision requires all four, and is re-made whenever any of
them changes — not once at login.

```
VERIFY → TRUST → OBSERVE → ANALYSE → SCORE → ADAPT → DEFEND
```

## Component map

```
┌─ ENDPOINT ──────────────────────────────────────────────────┐
│  NETRA CLIENT (Electron + React + TypeScript)               │
│    renderer ──preload bridge──> main process                │
│                          │                                   │
│                          │ named pipe (Windows) / UDS (unix) │
│                          ▼                                   │
│  NETRA AGENT (Rust service)                                  │
│    identity · posture · collectors · filter · queue · cache  │
└──────────┬───────────────────────────┬──────────────────────┘
           │ user auth (OIDC JWT)      │ device auth (mTLS + Ed25519)
           ▼                           ▼
┌──────────────── NETRA BACKEND (Go modular monolith) ────────┐
│ identity · device · telemetry · risk · behaviour · policy   │
│ application · resource · incident · audit · simulator        │
└──────┬──────────────────────┬────────────────┬──────────────┘
       ▼                      ▼                ▼
  PostgreSQL           Keycloak (OIDC)   Python analytics
       ▲                                 (scikit-learn, async)
       │ REST + SSE
  SOC DASHBOARD                    DEMO APPLICATIONS
```

## Component responsibilities

| Component | Owns | Must never |
|---|---|---|
| Electron client | Sign-in, launcher, security status, notifications | Collect telemetry, compute risk, hold the device key, expose `fs`/`shell`/`child_process`/`net` to the renderer |
| Rust agent | Device key and identity, posture, collectors, local filter, bounded queue, policy cache | Compute authoritative risk, upload raw unfiltered telemetry |
| Go backend | Authoritative risk, policy decisions, correlation, persistence, audit, all authorization | Trust a client-supplied risk score, posture claim, or user identity |
| Python analytics | Baselines, z-scores, Isolation Forest, anomaly scores | Sit in the synchronous decision path |
| SOC dashboard | Investigation and explainability | Hold business logic or bypass RBAC |

The client is **not** the security agent; the agent is **not** the decision
maker. Keeping these boundaries sharp is what makes the trust model auditable.

## The core mechanism: user ↔ device binding

This is what distinguishes NETRA from single sign-on. A session is bound
cryptographically to both a verified human and a verified device:

```
Electron → backend : begin session (OIDC token)
backend  → Electron: nonce
Electron → agent   : sign this nonce            (over local IPC)
agent    → Electron: Ed25519 signature          (private key never leaves the agent)
Electron → backend : {oidc_token, device_uid, nonce, signature}
backend            : verify JWT
                   ∧ verify signature against the enrolled public key
                   ∧ device state = ACTIVE
                   ∧ heartbeat fresh
                   → session bound to user AND device
```

A stolen token alone is not enough; a compromised device alone is not enough.

*Status: designed. Implemented in Phases 3 and 4.*

## Decisions and their reasons

### Modular monolith, not microservices

One Go process with strictly separated packages (`internal/identity`,
`internal/device`, …). Module boundaries are enforced by package structure, so
any module can be extracted into a service later without redesign. Twenty
services at prototype scale would add operational cost and no capability.

### No NATS, no Redis

The specification permits an event bus "only if it provides a real benefit". At
this scale it does not. PostgreSQL `LISTEN/NOTIFY` plus an in-process bounded
worker pool gives event-driven risk recomputation with no additional
infrastructure, behind a `Bus` interface so NATS can be introduced later without
touching call sites. Nonces, sessions and cached risk live in PostgreSQL too:
one datastore means one backup and one restore path, which also serves the
air-gapped deployments the specification anticipates.

### JSON on the wire, Protocol Buffers as the schema of record

Event structure is defined once in `proto/`. The transport ships JSON first
because it is debuggable and needs no toolchain. Protobuf encoding is
introduced during benchmarking, where a measured bytes-on-wire reduction is
worth demonstrating — rather than on day one, where it is only friction.

### Forward-only migrations

The audit log is evidentiary. An automated "down" path that can drop history is
a liability, so corrections are made by writing a new forward migration.

### Explainability is a data-model property

`risk_scores` stores the six dimension sub-scores; `risk_factors` stores the
individual signal contributions. A score is never stored without the reasons
that produced it, so "why did risk increase?" is answerable from the database
rather than reconstructed from logs.

## Data model

Implemented in migration `0001_init.sql`:

`users` · `devices` · `enrollment_tokens` · `device_posture` · `applications` ·
`resources` · `sessions` · `events` · `audit_logs`

Added in later phases: `risk_scores`, `risk_factors`, `behaviour_profiles`,
`policies`, `policy_decisions`, `incidents`, `incident_events`,
`incident_notes`.

Notable choices:

- `devices` has **no** private-key column. The private key never leaves the
  endpoint, so there is nowhere to put it by design.
- `device_posture` is a history table. An investigator needs posture as it was
  at the time of an event, not only the latest reading.
- `sessions.user_id` and `sessions.device_id` are both `NOT NULL`: NETRA has no
  concept of a user-only session.
- `events.occurred_at` is endpoint time and untrusted; `events.received_at` is
  authoritative server time.
- `audit_logs` is append-only and hash-chained — each row commits to its
  predecessor's hash, so removal or edit of history is detectable.
- `event_type` is `TEXT` with a `CHECK` rather than an enum, so new event types
  can be added without a blocking type migration.

## Scaling path

The prototype is one binary and one database. The interfaces are drawn so the
same code scales out:

```
Prototype :  Endpoint → Go backend → PostgreSQL
Scaled    :  Endpoints → Gateway → Event bus → Risk workers
                                             → Policy services → Data layer → SOC
```

Backend modules are stateless; session and risk state live in the database, so
horizontal scaling requires no redesign.
