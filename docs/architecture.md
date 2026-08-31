# Architecture

## High-level data flow

```
Controlled lab / client
        │  (in this prototype: LocalSimulatedHoneypot + simulator)
        ▼
  Honeypot Adapter (base.py / cowrie.py / local.py)
        ▼
  Event Collector (background thread)  ──► WebSocket bus (live feed)
        ▼
  Normalize → Deduplicate → Sessionize (telemetry/pipeline.py)
        ▼
  Feature Extraction (19 features, version v1)
        ▼
  ┌───────────────┬──────────────────┬───────────────────┐
  ▼               ▼                  ▼                   ▼
Classifier    Anomaly (IF)       Sequence (Markov)    (explanations)
  ▼               ▼                  ▼
  └───────────────┴──────┬──────────┘
                         ▼
                 Risk Engine (0–100, severity)
                         ▼
          Timeline Engine  +  Attack Graph (NetworkX→Cytoscape)
                         ▼
              Adaptive Deception Engine (safe policies)
                         ▼
               decoy environment / rollback / audit
                         ▼
              Analytics  +  SOC Dashboard (WebSocket live)
```

## Backend modules

- **REST/WS layer** (`app/api/`): FastAPI routers; `Bearer` JWT auth; role-based access;
  `/ws` WebSocket for live telemetry.
- **Orchestration** (`app/services/analysis_service.py`): single analysis entry point that
  chains features → classify → anomaly → predict → risk → timeline → graph → explain →
  deception and persists results.
- **ML/training** (`app/services/training_service.py`): generates synthetic labelled
  sessions and trains classifier, anomaly, and sequence models, persisting artifacts and
  registry rows.
- **Models** (`app/ml/`): classifier (LR/RF/XGB), Isolation Forest anomaly, Markov
  predictor, SHAP-proxy explainer.
- **Persistence** (`app/models/models.py`): SQLAlchemy ORM; schema created via
  `Base.metadata.create_all` on startup.

## Key design decisions

- **Module-level `DecoyEnvironment` singleton** so request-scoped `DeceptionEngine`
  instances share consistent active-decoy state (verified via `/deception/environment`).
- **`metadata` → `payload` column mapping**: SQLAlchemy renames the `metadata` attribute to
  `payload` (DB column key `"metadata"`); Pydantic schema field stays `metadata`.
- **Simulator determinism**: fixed RNG seed + explicit start time → reproducible sessions
  (used by tests and the experiment runner).
- **Local-only safety**: simulated attacker sources are private lab IPs; all deception is
  predefined, reversible, audited.

## Frontend

React 18 + TypeScript + Vite + Tailwind + Recharts. `useLiveEvents` opens `/ws` (Vite proxy
→ backend), replays history then streams live events. `services/api.ts` injects the JWT and
talks to `/api/*`. Custom SVG `AttackGraph` renders Cytoscape.js-format nodes/edges.
