# Honeypot sensor for Linux hosts. Build from the project root so the
# pretrained models are in the context:
#
#   docker build -f honeypot-backend/Dockerfile -t honeypot-sensor .
#
# Run it with docker-compose.yml (host networking + NET_ADMIN for iptables).
FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cicids2017_feature_schema.json cicids2017_portscan_model.joblib ./
COPY ["feature_schema (1).json", "reconnaissance_model (1).joblib", "./"]
COPY honeypot-backend ./honeypot-backend

WORKDIR /app/honeypot-backend
# Train the behaviour model at build time so the image starts with one.
# Retrain later with labelled data: docker compose run sensor python -m sensor.tools.train_behaviour --db ...
RUN python -m sensor.tools.train_behaviour --lab-sessions 600

ENV HONEYPOT_SENSOR_CONFIG=/app/honeypot-backend/sensor/docker.json
CMD ["python", "-m", "sensor.main"]
