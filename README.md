# AI-Based Adaptive Honeypot

SOC-style dashboard for an **AI-Based Adaptive Honeypot for Continuous Cybersecurity Threat Detection and Attack Behavior Analysis**.

A self-contained React + TypeScript + Vite + Tailwind frontend with an in-browser **Demo Mode** that simulates synthetic honeypot telemetry across three controlled attack categories:

- SSH Brute Force / Credential Guessing
- Web Application Scanning
- Payload Delivery Simulation (read-only, never executed)

All synthetic data uses documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). No real attacks and no offensive payloads.

## Pages

- Security Overview Dashboard
- Live Attack Monitor (real-time event stream + filters)
- Attack Analysis (attacker profiles, behavior patterns, risk scores)
- AI Analysis (classification, confidence, adaptive decisions, pipeline)
- Adaptive Honeypots (status + adaptation history)
- Threat Intelligence (IP / hash / behavioral indicators)
- Sessions (captured session timelines)
- Analytics (trends, distributions, AI performance)

## Getting started

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build      # typecheck + production build
```

## Demo Mode

Use the controls in the top-right to Start/Pause the simulation, Reset data, or manually Generate an SSH / Web / Payload event. The live feed updates in near-real-time via an in-app event bus mirroring WebSocket semantics.
