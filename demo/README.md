# Demo applications

Five local applications with distinct sensitivity levels. **Phase 11.**

| Application | Sensitivity |
|---|---|
| Mail | INTERNAL |
| Collaboration | INTERNAL |
| Internal Portal | INTERNAL |
| Operations Portal | SENSITIVE |
| Critical Resource Portal | CRITICAL |

They exist so the same user behaviour produces different risk depending on what
is being accessed — the contextual part of NETRA's trust model.

Each calls the NETRA access-control API for its decisions and holds no policy
logic of its own. None of them reverse-engineer, bypass, or inject credentials
into any third-party system; they are purpose-built applications that federate
through legitimate OIDC.
