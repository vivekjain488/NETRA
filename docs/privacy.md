# Privacy

Security telemetry is not employee surveillance. In NETRA that distinction is
enforced by engineering, not by policy text.

## What is collected

| Category | Examples |
|---|---|
| Authentication | sign-in, sign-out, step-up verification outcomes |
| Device posture | OS build, disk encryption state, agent health, identity validity |
| Application metadata | which approved application was launched or accessed |
| Resource access | which classified resource was accessed, and its sensitivity |
| Privilege changes | elevation and group membership changes |
| Network metadata | destination category, ASN, connection counts |
| Security events | OS-reported security events relevant to endpoint trust |
| Policy and risk | decisions made, and the factors that drove them |

## What is never collected

- Keystrokes
- Screen contents or screenshots
- Camera or microphone
- Message, email or document **contents**
- Browsing history unrelated to approved applications
- Personal files or their contents
- Credentials or tokens of any kind

## How this is enforced

**The schema has no field for it.** `netra_core::Event` carries correlation
identifiers, a type, a severity and a bounded metadata map. There is no content
field. A collector cannot report a keystroke or a message body without adding a
field to a shared type — a change that is visible in review, not a
configuration toggle.

**The client denies every permission.** The Electron main process installs a
blanket `setPermissionRequestHandler` denial and a `setPermissionCheckHandler`
returning `false`. Camera, microphone, screen capture and geolocation are
refused unconditionally, because NETRA has no legitimate use for any of them.
A permissive default that a later change could widen would be the wrong shape.
See `electron/main/security.ts`.

**Content-Security-Policy limits where data can go.** `connect-src` in the
client is restricted to the NETRA backend, so a compromised renderer cannot
exfiltrate to an arbitrary origin.

**Data stays under the operator's control.** The deployment has no dependency
on any cloud provider or third-party telemetry service. Everything runs on
infrastructure the organisation controls, which is what makes air-gapped
deployment possible later.

## What the user sees

The endpoint client is deliberately calm. It shows the user their own security
state — device trusted, session secure, additional verification required — and
nothing about anybody else. It does not present itself as a monitoring tool,
because it is not one.

## Data retention

- The endpoint queue is bounded by both event count and total bytes, and evicts
  oldest-first. Dropped events are **counted**, so shedding is visible to the
  SOC rather than silent.
- Backend retention policy is defined in Phase 15.

## Status

| Control | State |
|---|---|
| Event schema without content fields | Implemented |
| Blanket permission denial in the client | Implemented |
| Client CSP restricting `connect-src` | Implemented |
| Bounded, accounted local queue | Implemented |
| Administrator-facing telemetry policy | Phase 6 |
| Backend retention limits | Phase 15 |
