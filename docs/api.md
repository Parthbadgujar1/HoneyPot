# REST API reference

Base prefix: `/api`. Auth: `Authorization: Bearer <JWT>`. OpenAPI docs at
`http://localhost:8000/docs`.

## Auth

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/auth/login` | public | form: `username`, `password` | `{access_token, token_type, user}` |
| POST | `/auth/register` | public | JSON: username, password, role | `201 {id, username, role}` |
| GET | `/auth/me` | any | — | `{id, username, email, role, is_active, created_at}` |

## Dashboard

`GET /dashboard/summary` → `{total_sessions, active_sessions, high_risk_sessions, anomalies, total_events, predictions, adaptive_actions}`

## Events

- `GET /events?page&page_size&session_id&service&event_type&search&sort_by&sort_dir` → `{total, page, page_size, items[]}`
- `GET /events/{id}` → event object

Event fields: `id, event_ref, session_id, timestamp, source, destination, service, event_type, action, target, result, username, command, metadata, is_anomaly, risk_score`.

## Sessions

- `GET /sessions?page&page_size&severity&service&risk_min` → `{total, items[]}`
  summary: `id, session_ref, source, service, start_time, end_time, duration_seconds, event_count, is_active, risk_score, severity`
- `GET /sessions/{id}` → summary + `{classification, anomaly, prediction, features, deception_actions}`
- `POST /sessions/{id}/analyse` (ANALYST+) → `{status, analysis}` (classification, anomaly, prediction, risk, timeline, graph, explanation, deception)
- `GET /sessions/{id}/timeline` → array of timeline entries
- `GET /sessions/{id}/graph` → Cytoscape `{nodes, edges, stats}`
- `GET /sessions/{id}/prediction` → `{top1, top1_probability, top_predictions, input_sequence, model, model_version}`
- `GET /sessions/{id}/explanation` → `{classification, risk, anomaly}`

## Anomalies

- `GET /anomalies?min_score&label` → `{total, items[]}`
- `GET /anomalies/stats` → `{distribution, anomalies, normal}`

## Behaviours

`GET /behaviours` → `{total, items[], distribution}`

## Risk

- `GET /risk?severity` → `{total, items[]}`
- `GET /risk/stages` → `{stages[]}` (7 behavioural stages)

## Deception

- `GET /deception/environment` → `{decoys[], active_count}`
- `GET /deception/actions?session_id` → `{items[]}`
- `POST /deception/actions/{id}/rollback` (ADMIN) → `{action_id, policy_id, status, decoy, environment}`
- `POST /deception/sessions/{id}/evaluate` (ANALYST) → stub confirmation

## Honeypot

- `GET /honeypot/status` → `{adapter, collector, db, scenarios[], environment}`
- `GET /honeypot/scenarios` → `[{id, label, description}]`
- `POST /honeypot/simulate?scenario=...&n_sessions=N` (RESEARCHER+) → `{emitted, scenario, sessions}`

## Models

- `GET /models` → `{items[]}`
- `GET /models/{id}/metrics` → `{model, version, metrics}`
- `POST /models/train` (RESEARCHER+) → `{status, results{classifier, anomaly, sequence}}`
- `POST /models/{id}/activate` (RESEARCHER+) → `{status, model_type, version}`

## Analytics

`GET /analytics/events-over-time?bucket=minute|hour|day`, `/classification-distribution`,
`/risk-distribution`, `/service-usage`, `/anomaly-distribution`, `/session-durations`,
`/behaviour-transitions`, `/adaptive-actions` — all return arrays.

## Audit & system

- `GET /audit?page&page_size&action` (ANALYST+) → `{total, items[]}`
- `GET /system/status` → `{services, models, config}`
- `GET /system/metrics` → `{summary, events_over_time}`

## Health (no /api prefix)

- `GET /health` → `{status: "ok", service}`
- `GET /ready` → `{status: "ready", db}`

## WebSocket

`ws://<host>/ws` — no auth. Replays last 100 events, then streams live:
`{"kind":"event","data":{...}}`; keepalive `{"kind":"ping"}` every 30s of inactivity.
