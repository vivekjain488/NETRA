# Demonstration

## The rule

Demo mode drives the **real** pipeline. Scenarios generate genuine events that
travel the real ingest path, the real risk engine, the real policy engine and
the real correlation. No score, decision or incident is ever written directly.

```
SIMULATOR → EVENTS → RISK ENGINE → POLICY ENGINE → INCIDENT → SOC
```

Everything the simulator creates is marked `SIMULATOR` at the source, so
synthetic activity is always distinguishable from a real endpoint's in the
event stream.

## Running it

In the console, open **Demonstration** and press a scenario. From the API:

```bash
ADMIN=$(curl -s -X POST http://localhost:8080/api/v1/dev/token \
  -H 'Content-Type: application/json' -d '{"subject":"priya","roles":["ADMIN"]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://localhost:8080/api/v1/demo/scenarios/compromised-session \
  -H "Authorization: Bearer $ADMIN"
```

Running a scenario is an administrator action and is audited: synthetic
activity that looks real in the event stream must be traceable to whoever
caused it.

## Scenarios

| Name | Shows |
|---|---|
| `normal-session` | A known user on a known device stays in the LOW band |
| `new-device` | The `NEW_DEVICE` factor appears and risk rises |
| `unusual-login-time` | Deviation judged against *this user's* baseline, not an office norm |
| `sensitive-resource` | Identical behaviour, stricter answer, because of what was reached |
| `abnormal-volume` | The z-score against the user's own history |
| `network-anomaly` | An unfamiliar network contributes |
| `compromised-session` | The full escalation below |

## The hero demonstration

`compromised-session` introduces one signal per step. This is a real run, not a
target:

| Step | Risk | Δ | Level | Decision |
|---|---:|---:|---|---|
| Normal sign-in, usual device | 9 | | LOW | ALLOW |
| Credential used from a new device | 29 | +20 | LOW | ALLOW |
| Sign-in at 01:47 from an unfamiliar network | 56 | +27 | ELEVATED | VERIFY |
| Classified resource reached | 81 | +25 | HIGH | RESTRICT |
| Abnormal read volume | 100 | +19 | CRITICAL | ISOLATE |

At CRITICAL the policy engine isolates the session, opens one incident and
alerts the SOC. The analyst then sees, in the Incidents view, a single record
with the affected user and device, the peak risk, every contributing factor,
and a timeline that merges endpoint events, risk changes and policy decisions
into one ordered narrative.

The score lands on 100 rather than the 94 the original specification sketched.
That is the number the engine computes from the accumulated context, and it is
reported as computed. Tuning weights to hit a rehearsed figure would defeat the
purpose of a demonstration that runs the real pipeline.

## Seeded history, stated openly

Behavioural baselines need history, and a twenty-minute demonstration has none.
The simulator seeds roughly 30 days of ordinary activity for the demo user
before the first scenario runs — steady but not identical daily volumes, so the
standard deviation behind the z-score is usable rather than zero.

The baselines are therefore **simulator-seeded, not learned from real people**.
The mechanism judging deviation is the real one; the history it judges against
is synthetic.

## Resetting

Scenarios accumulate state deliberately: risk is cumulative within a session.
To start from a clean slate:

```bash
docker exec netra-postgres psql -U netra -d netra -c "
  TRUNCATE sessions, events, risk_scores, risk_factors, policy_decisions,
           incidents, behaviour_profiles, device_posture, audit_logs
  RESTART IDENTITY CASCADE;
  DELETE FROM devices WHERE device_uid LIKE 'netra-sim-%';"
```

## What a reviewer should check

The point of this design is that the demonstration is falsifiable. A sceptical
reviewer can verify each claim independently:

- **The events are real.** Open the Events page, or query
  `/api/v1/events?session_id=…`, and see the rows the scenario produced.
- **The score is computed, not written.** `/api/v1/risk/{session_id}` returns
  every factor; the contributions sum exactly to the score.
- **The decision cites its policy.** Each entry on the Policies page names the
  policy and version in force when the decision was made.
- **The audit chain is intact.** The Audit page verifies it on every load, and
  reports the exact sequence number if it ever breaks.
