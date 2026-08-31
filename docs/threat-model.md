# Threat model

## Assets

| Asset | Why it matters |
|---|---|
| Device private keys | Compromise permits device impersonation and forged telemetry |
| OIDC tokens | Compromise permits user impersonation |
| Telemetry | Integrity determines whether risk scoring is meaningful |
| Risk scores and factors | Drive access decisions |
| Policies | Determine what is allowed |
| Audit log | The evidentiary record of what happened |
| Critical-resource access | The thing ultimately being protected |

## Trust boundaries

See [security.md](security.md) for the boundary table (B1–B7) and its
implementation status.

## Threat actors and mitigations

### 1. External attacker with stolen credentials

*Capability:* valid username, password and possibly an MFA code.

*Mitigation:* a session requires device attestation as well as a token, so
credentials alone do not produce a session on an unenrolled device. If the
attacker reaches an enrolled device, the new-device, unusual-time and
behavioural-deviation signals raise risk and the policy engine escalates.

*Residual:* an attacker operating from an already-enrolled device during normal
hours, behaving like the user, is the hardest case. Resource sensitivity
weighting is the remaining defence.

### 2. Compromised endpoint

*Capability:* code execution as the user.

*Mitigation:* the private key is held by the agent, not the client; posture is
treated as a claim; anomalous process and network signals raise risk.

*Residual:* **an attacker with local administrator rights on the endpoint can
suppress or forge agent telemetry.** Hardware-backed key storage raises the cost
of key theft but does not solve suppression. This is stated plainly rather than
mitigated by assertion.

### 3. Malicious insider

*Capability:* legitimate credentials and a legitimate device.

*Mitigation:* behavioural baselines detect deviation from the individual's own
history; sensitivity weighting makes unusual access to `CRITICAL` resources
score far higher than the same pattern against `INTERNAL` ones; every access is
audited.

*Residual:* slow, low-volume exfiltration within normal patterns.

### 4. Privileged insider (administrator)

*Capability:* can change policy and revoke devices.

*Mitigation:* policies are immutable versioned rows, so a decision always cites
the exact policy in force; the audit log is hash-chained, so silent edits are
detectable; administrator actions are themselves audited.

*Residual:* collusion between an administrator and an auditor.

### 5. Telemetry tampering

*Capability:* forge or replay events to hide activity or frame a user.

*Mitigation:* events are signed by the device key with a nonce and timestamp;
replayed nonces are rejected; the server stamps its own receipt time; the
backend cross-checks endpoint claims where it independently can.

*Residual:* suppression at source on a fully compromised endpoint. Missing
heartbeats and stale posture make silence itself a risk signal.

### 6. Token theft from the client

*Capability:* another process on the endpoint attempts to read the session
token.

*Mitigation:* `contextIsolation` and `sandbox` in the renderer, OS-protected
token storage, short-lived tokens, and the device binding requirement — a stolen
token is not usable elsewhere without the device key.

*Residual:* malware running as the same user.

### 7. Lateral movement

*Capability:* pivot from one system to another after initial access.

*Mitigation:* risk is re-evaluated on every meaningful event, not only at login,
so a session that begins benign and turns hostile is re-scored mid-session.

### 8. Compromised administrator console

*Mitigation:* RBAC separates `ADMIN` (manage), `SECURITY_ANALYST`
(investigate) and `AUDITOR` (read audit). No single role can both act and erase
the record of acting.

## What NETRA does not defend against

Stated explicitly, because overclaiming is the fastest way to lose trust in a
security product:

- A fully compromised endpoint with local administrator rights can suppress
  telemetry. NETRA detects the *silence*, not the activity.
- NETRA is not antivirus, EDR or DLP, and does not attempt to block malware
  execution or file exfiltration at the OS level.
- Physical attacks against an unlocked endpoint are out of scope.
- Supply-chain compromise of NETRA's own dependencies is mitigated only by
  dependency auditing and signed builds (Phase 15/16), not eliminated.

## Status

This is a documented model, not a completed assessment. The system has not
undergone external security review.
