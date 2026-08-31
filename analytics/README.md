# Analytics

Behavioural baselines and anomaly scoring. **Phase 8.**

Python with scikit-learn, running **asynchronously** and never in the
synchronous decision path (spec §21, §22). It reads events from PostgreSQL,
computes per-user baselines, and writes anomaly scores back for the Go risk
engine to read on its next evaluation.

Planned layout:

```
baseline/   login-hour histograms, device and application frequency,
            access-rate statistics, network destination profiles
anomaly/    z-score, moving average, frequency analysis, Isolation Forest
models/     persisted model artefacts, versioned alongside the profile schema
service/    FastAPI worker
```

Deliberately excluded: deep learning, GPUs, and large language models. The
detection stack is rules plus statistics plus a small model, not a black box.
