# Security

Security is priority one for this system, ahead of feature count and ahead of
visual polish. This document states what is implemented today and what is
planned, without conflating the two.

## Trust boundaries

| # | Boundary | Control | State |
|---|---|---|---|
| B1 | Renderer → Electron main | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, strict CSP, explicit preload allowlist | Implemented |
| B2 | Electron → agent | Named pipe (Windows) / Unix socket (0600), per-boot token, narrow method surface | Implemented |
| B3 | Agent → backend | mTLS plus Ed25519 request signing with nonce and timestamp | Signing done; mTLS Phase 15 |
| B4 | Client → backend | OIDC JWT validated against JWKS, **plus** device attestation | Implemented |
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

**A session requires both a user and a device.** Signing in is a four-step
exchange: obtain a user token, request an attestation nonce, have the agent
sign it, then present all of it together. A stolen token alone produces no
session, and a device with no user produces none either. The nonce is issued to
one specific user, single-use, and expires in two minutes; the device must also
have sent a heartbeat within the last fifteen minutes, so a device whose agent
has gone quiet stops conferring trust.

**The attestation message is its own scheme.** It carries a `NETRA-attest-v1`
prefix, distinct from the `NETRA-v1` prefix on agent request signatures, so an
intercepted heartbeat signature can never be presented as a sign-in proof. The
subject is bound into the signed bytes, so an attestation produced during one
person's sign-in cannot be lifted into another's on a shared device. The
backend returns the exact message to be signed rather than letting the client
assemble it, so a client bug cannot silently sign the wrong bytes.

**The agent never signs arbitrary bytes.** Its local IPC `attest` method takes
a nonce and a subject and constructs the message itself. There is no code path
by which a local process holding the IPC token can obtain an agent-plane
request signature — proven by a test that checks an attestation signature fails
to verify as a request signature.

**The IPC channel is narrow and local.** A Unix socket with owner-only
permissions, or a named pipe — not a loopback port every local process could
reach. A per-boot token, regenerated on every start so it cannot be harvested
once and reused, is compared in constant time. Requests are bounded in size,
and the method surface is two calls.

**The access token never reaches the renderer.** It is held in the Electron
main process; the renderer receives only session state. A renderer compromised
by XSS cannot exfiltrate it.

**The endpoint reports facts; the backend decides what they are worth.** An
agent submits observations — encryption on, firewall on, OS version — and the
control plane scores them. An endpoint that computed its own trust score would
be asserting its own trustworthiness, and a compromised one would simply report
100. The posture report has no score field, and a submission containing one is
rejected. The device a report is attributed to comes from the verified request
signature, never the body, so one agent cannot report on another's behalf.

**Unknown is not the same as satisfied.** Every posture signal is
three-valued: satisfied, not satisfied, or not determined. A collector that
failed to run scores zero and records why, so it can never be mistaken for one
that found a control enabled. Endpoint claims are stored marked `reported`;
only what the backend established itself is marked `verified`, and an
assessment resting on any endpoint claim reports `verified: false` — which is
the honest answer today.

**A score always comes with its reasons.** Contributions sum exactly to the
score, so the explanation an analyst reads reconciles with the number rather
than approximating it. The weights are configuration and the model version is
stored with every assessment, because a historical score is only interpretable
alongside the model that produced it.

**Silence is a signal.** A device whose agent has not reported within fifteen
minutes loses its agent-health points and cannot establish a new session. NETRA
cannot see what a silent endpoint is doing, so it stops conferring trust rather
than quietly continuing to.

**Generated secrets, never committed ones.** `.env.example` ships every secret
blank and `make env` generates a random 32-character value for each. A shared
default development password is the first thing an attacker tries, and the
habit follows the code into production.

**Dependency hygiene.** `npm audit` reports zero vulnerabilities across both
Node projects. Electron was upgraded from 33 to 44 during Phase 1 specifically
to clear a `contextBridge` prototype-setter advisory that bears directly on the
IPC boundary above.

## Planned

**Rate limiting where guessing is the risk.** Enrollment, token issue and
telemetry ingest are bounded per caller. The first two are guessable targets
and an unbounded endpoint lets an attacker try as fast as the network allows;
the third is an authenticated but automated write path where a runaway agent
can fill a table faster than an operator notices. The limiter keys on the peer
address, never on a forwarded header — keying on something client-controlled
would let an attacker reset their own limit. It is a fixed window and
per-instance, which is stated rather than implied to be a cluster-wide
guarantee.

## Not implemented

Stated plainly rather than left to inference:

| Control | Status |
|---|---|
| mTLS between agent and backend | Designed. Ed25519 request signing with replay protection is implemented, which is the property that matters; mutual TLS would add transport binding on top. |
| Interactive OIDC sign-in | Backend validates tokens and the realm is defined; neither client performs the authorization-code exchange. Both use the development endpoint, which cannot exist outside development. |
| Signed agent and client builds | `electron-builder` is configured; no signing identity is wired up. |
| Distributed rate limiting | The current limiter is per-instance. |
| Windows anything | Written, compiles under `cfg(windows)`, never executed on Windows. |

## Reporting

This is a prototype under active development and has not undergone external
security review.
