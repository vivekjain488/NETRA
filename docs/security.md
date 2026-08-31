# Security

Security is priority one for this system, ahead of feature count and ahead of
visual polish. This document states what is implemented today and what is
planned, without conflating the two.

## Trust boundaries

| # | Boundary | Control | State |
|---|---|---|---|
| B1 | Renderer → Electron main | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, strict CSP, explicit preload allowlist | Implemented |
| B2 | Electron → agent | Named pipe (Windows ACL) / Unix socket (0600), per-boot token, peer verification | Phase 4 |
| B3 | Agent → backend | mTLS plus Ed25519 request signing with nonce and timestamp | Signing done; mTLS Phase 15 |
| B4 | Client → backend | OIDC JWT validated against JWKS, **plus** device attestation | JWT done; attestation Phase 4 |
| B5 | Backend → database | Least-privilege role, parameterised queries only | Implemented |
| B6 | SOC → backend | RBAC per route, every privileged action audited | Implemented |
| B7 | Demo apps → backend | Access decisions come from the policy API; apps hold no policy logic | Phase 11 |

## Invariants

These hold regardless of phase, and are what the rest of the design rests on:

1. **Risk is computed only by the backend, from stored events.** No API accepts
   a risk score, a risk hint, or a trust score from a client.
2. **The device private key never leaves the endpoint.** The `devices` table has
   no column for it.
3. **Endpoint claims are claims.** Agent-reported posture is stored with a
   `verified` flag and scored as a risk indicator, never treated as proof.
4. **Every security decision is auditable.** Decisions cite the exact policy
   version in force at the time.
5. **Endpoint time is untrusted.** `occurred_at` comes from the endpoint;
   `received_at` is stamped by the server and is authoritative.

## Implemented today

**Request correlation.** Every response carries a server-generated
`X-Request-ID`. A client-supplied value is deliberately discarded — trusting it
would let an attacker collide or poison audit correlation. Covered by test.

**Error handling that does not leak.** All errors are RFC 7807
`application/problem+json`. Panics return a generic 500 with the detail logged,
not returned. Database errors are passed through a redactor that strips the DSN
password before the error is logged or surfaced. Covered by tests.

**Security headers.** `X-Content-Type-Options: nosniff`, `X-Frame-Options:
DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and a
restrictive CSP on the JSON API.

**CORS without wildcards.** Only explicitly configured origins are permitted;
an unconfigured origin receives no `Access-Control-Allow-Origin` at all.
Covered by test.

**Electron hardening.** `contextIsolation`, `sandbox`, no `nodeIntegration`,
CSP applied to every response, blanket permission denial, navigation confined to
the application origin, external links routed to the system browser, single
instance lock.

**A minimal IPC surface.** The renderer receives four zero-argument functions.
`ipcRenderer` is not exposed and no channel name is accepted from the page, so a
renderer compromised by XSS gains four read-only queries rather than IPC.

**No hard-coded configuration or secrets.** Every value comes from the
environment and is validated at load; invalid configuration fails startup rather
than silently degrading a control. `.env` is gitignored; `.env.example` carries
no real credentials.

**Container hardening.** Multi-stage builds, no toolchain in the runtime layer,
non-root user, healthchecks.

**Identity, never passwords.** NETRA delegates authentication entirely. Tokens
are validated for signature, issuer, audience and expiry; the audience check is
mandatory, because without it a token minted for any other client of the same
realm would be accepted here. A rejected token yields a generic 401: telling a
caller whether a token was expired, wrongly signed or wrongly addressed turns
the endpoint into a probing oracle.

**Roles from the token, not the row.** The identity provider is authoritative,
so a role revoked upstream takes effect on the very next request rather than
when a cached copy expires. Role names NETRA does not define are discarded, so
an identity provider compromise cannot invent new authority inside NETRA.

**Immediate account disablement.** A disabled user presenting a still-valid
token is refused and the refusal is audited.

**A contained development authenticator.** `NETRA_DEV_AUTH_ENABLED` mints local
tokens so tests and demonstrations do not require a live identity provider.
Four properties contain it: configuration load fails unless
`NETRA_ENV=development`; the signing key is random per process and never
written to disk; it accepts only its own non-URL issuer, so it can never
validate something claiming to come from the real provider; and the route is
not mounted at all when it is off. Each of these is covered by a test.

**Audit that resists rewriting.** Every record commits to its predecessor's
hash. Appends are serialised by a PostgreSQL advisory lock so two writers
cannot fork the chain. Verification is exposed on the read API, so an analyst
sees whether the log can be trusted; editing a row directly in the database is
detected and the breaking sequence number reported. Authorization denials and
audit reads are themselves audited. Authentication *failures* are logged but
not audited: anonymous traffic would otherwise let anyone grow the audit table
without limit.

**Device identity that cannot be forged or moved.** Each endpoint generates an
Ed25519 key pair at enrollment and keeps the private half. Every agent request
is signed over a canonical string covering the method, path, timestamp, nonce
and a digest of the body — so a captured signature cannot be replayed, moved to
another endpoint, or reused with an edited body. The body is covered by its
digest rather than inline, so signing cost does not grow with a telemetry
batch. Timestamps outside a five-minute window are rejected in **both**
directions: accepting future timestamps would let an endpoint mint requests
that stay valid after its key is revoked. Nonces are consumed through a unique
constraint, so two concurrent replays cannot both pass a check and then both
insert.

**Enrollment is never anonymous.** A device is registered only against a
single-use, expiring token issued by an administrator. Only the token's
SHA-256 hash is stored, so reading the database does not yield a usable token,
and the token is never written to the audit log — an audit reader must not be
able to enrol a device from the record. Invalid and spent tokens are reported
identically, so a guess cannot reveal whether a token was ever real. Failed
attempts are audited; they require presenting a token value, so the volume is
bounded.

**Revocation is immediate.** A revoked device still holds a key that signs
correctly, so state is what stops it — checked on every request, before the
signature is even verified.

**The private key has nowhere to leak to.** The `devices` table has no column
for one, the enrollment payload has no field for one, and the agent's
`DeviceKey` has a hand-written `Debug` implementation so an accidental `{:?}`
cannot print it. Each of these is covered by a test.

**Generated secrets, never committed ones.** `.env.example` ships every secret
blank and `make env` generates a random 32-character value for each. A shared
default development password is the first thing an attacker tries, and the
habit follows the code into production.

**Dependency hygiene.** `npm audit` reports zero vulnerabilities across both
Node projects. Electron was upgraded from 33 to 44 during Phase 1 specifically
to clear a `contextBridge` prototype-setter advisory that bears directly on the
IPC boundary above.

## Planned

| Control | Phase |
|---|---|
| OIDC token validation, JWKS rotation | 2 |
| RBAC across all planes | 2 |
| Hash-chained audit writes and chain verification | 2 / 15 |
| Administrator-issued single-use enrollment tokens | 3 |
| Ed25519 signed agent requests, replay protection | 3 |
| Encrypted local agent state | 3 |
| mTLS between agent and backend | 15 |
| Rate limiting | 15 |
| Signed agent and client builds | 16 |

## Reporting

This is a prototype under active development and has not undergone external
security review.
