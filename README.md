# HoneyPot

AI-adaptive honeypot for network deception and threat intelligence.

- `honeypot-backend/sensor/`: the sensor. Decoy SSH, HTTP and bait services, reconnaissance detection with the trained models, adaptive deception, firewall blocking, an operator console and threat-intel exports. See [sensor/README.md](honeypot-backend/sensor/README.md).
- `honeypot-backend/`: FastAPI backend for the earlier detection API and dashboard data.
- `honeypot-frontend/`: React dashboard.
- Trained models: `cicids2017_portscan_model.joblib`, `reconnaissance_model (1).joblib`.
