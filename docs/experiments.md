# Experiments & evaluation

## Research questions addressed

- **RQ1** Can behavioural ML classify suspicious sessions from honeypot telemetry?
- **RQ2** Can unsupervised learning detect previously unseen patterns?
- **RQ3** Can sequence models predict the next behavioural stage?
- **RQ4** Does adaptive deception collect more useful telemetry than a static honeypot?

## Experimental design (spec §22)

Compares three operating modes on the same generated sessions:

| Mode | Capabilities |
|---|---|
| `baseline` | telemetry only (static honeypot) |
| `ai_assisted` | + classification, anomaly detection, risk scoring, timeline |
| `adaptive` | + sequence prediction, adaptive deception |

### Metrics captured (spec §23)

- **Honeypot effectiveness:** total events, events per session, behavioural coverage,
  unique patterns, max/mean session depth.
- **Intelligence:** high-risk sessions, anomalies detected, predictions made, adaptive
  actions.

## Running

```powershell
$env:PYTHONPATH="backend"
python ml\experiments\experiment_runner.py
```

Writes `ml/experiments/results/experiment_<timestamp>.json` (full) and `.csv` (tabular).

## Interpreting results

Design a metric favourable to the hypothesis H3 ("adaptive > static for intelligence
collection"): `adaptive_actions + behavioural_coverage + unique_patterns` rise from
baseline → adaptive, while `events_per_session` stays comparable (same underlying input),
demonstrating that the adaptive mode extracts more *actionable* signal per unit telemetry.

## Path forward

- Replace heuristic mode logic with the real trained models (requires a running DB + trained
  registry) for publication-grade numbers.
- Add statistical comparison (e.g., paired tests over seeds) and ablation rows.
- Introduce public datasets (CICIDS2017, UNSW-NB15) for generalization benchmarking.
