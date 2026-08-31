# Demonstration

## Status

**The demonstration is not implemented yet.** It is delivered by Phases 11–13.
This document records the intended script so the components built beforehand
are shaped to serve it.

Nothing below currently runs. It is a plan, not a transcript.

## Principle

Demo mode drives the **real** pipeline. The simulator generates genuine events
that the real ingest path, the real risk engine, the real policy engine and the
real correlation engine process. No dashboard state is faked and no API
response is stubbed to make the UI look finished.

```
SIMULATOR → TELEMETRY API → RISK ENGINE → POLICY ENGINE → INCIDENT → SOC
```

Judges must be able to watch each stage happen, and to see the same event in
the database, in the risk factors and in the incident timeline.

## Hero scenario: compromised employee session

Opening state:

| Field | Value |
|---|---|
| User | Alice |
| Device | GOV-LAPTOP-01 |
| Status | TRUSTED |
| Risk | 12 / 100 |

Triggered steps, each an operator-initiated synthetic event flowing through the
real pipeline:

| Step | Trigger | Expected risk |
|---|---|---|
| 1 | New device | 12 → 35 |
| 2 | Unusual login time (01:47) | 35 → 52 |
| 3 | Sensitive resource access | 52 → 70 |
| 4 | Behaviour anomaly (abnormal access volume) | 70 → 84 |
| 5 | Network anomaly | 84 → 94 |

At 94 the policy engine reaches `CRITICAL`, applies `RESTRICT`, creates an
incident and raises a SOC alert.

The SOC analyst then sees one incident — not five disconnected alerts — with:

- the affected user, device and resource
- the risk score and every factor with its individual contribution
- the event timeline
- the attack path
- the policy action taken, citing the exact policy version in force

The risk figures above are **targets for the weighting model**, not measured
results. Actual values will be whatever the implemented engine produces, and
this document will be updated to match rather than the engine tuned to match the
document.

## Baselines

Behavioural baselines need history that a twenty-minute demonstration does not
have. The simulator seeds roughly 30 days of synthetic normal behaviour per
user, from which baselines are computed. This is stated openly: the baselines
are simulator-seeded, not learned from real users.
