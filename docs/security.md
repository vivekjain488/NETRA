# Security

Security is priority one for this system, ahead of feature count and ahead of
visual polish. This document states what is implemented today and what is
planned, without conflating the two.

## Trust boundaries

| # | Boundary | Control | State |
|---|---|---|---|
| B1 | Renderer → Electron main | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, strict CSP, explicit preload allowlist | Implemented |
| B2 | Electron → agent | Named pipe (Windows ACL) / Unix socket (0600), per-boot token, peer verification | Phase 4 |
| B3 | Agent → backend | mTLS plus Ed25519 request signing with nonce and timestamp | Phase 3 / 15 |
| B4 | Client → backend | OIDC JWT validated against JWKS, **plus** device attestation | Phase 2 / 4 |
| B5 | Backend → database | Least-privilege role, parameterised queries only | Implemented |
| B6 | SOC → backend | RBAC per route, every privileged action audited | Phase 2 |
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
