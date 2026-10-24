
import pandas as pd

REQUIRED_COLUMNS = {
    "source_id",
    "timestamp",
    "destination_port",
    "success",
}


def detect_reconnaissance(events):
    """
    Analyze synthetic or authorized lab connection events.

    Returns one summary record per source, using that source's
    latest event as the endpoint of the evaluation window.
    """
    missing = REQUIRED_COLUMNS - set(events.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    df = events.copy()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="raise"
    )
    df["destination_port"] = pd.to_numeric(
        df["destination_port"], errors="raise"
    )

    if df["destination_port"].isna().any():
        raise ValueError("Destination ports cannot be missing")

    if not df["destination_port"].between(1, 65535).all():
        raise ValueError("Destination ports must be between 1 and 65535")

    if df["source_id"].isna().any():
        raise ValueError("Source IDs cannot be missing")

    df["success"] = df["success"].astype(bool)

    results = []

    for source_id, group in df.groupby("source_id"):
        group = group.sort_values("timestamp")
        latest = group["timestamp"].max()

        recent = group[
            group["timestamp"] >= latest - pd.Timedelta(seconds=60)
        ]
        longer = group[
            group["timestamp"] >= latest - pd.Timedelta(minutes=10)
        ]

        recent_ports = int(recent["destination_port"].nunique())
        long_ports = int(longer["destination_port"].nunique())
        attempts = len(longer)

        failure_ratio = (
            float((~longer["success"]).mean()) if attempts else 0.0
        )

        reasons = []
        score = 0

        if recent_ports >= 10:
            reasons.append("Rapid scan: 10+ ports in 60 seconds")
            score += 60

        if long_ports >= 6:
            reasons.append("Sustained probing: 6+ ports in 10 minutes")
            score += 40

        if attempts >= 20:
            reasons.append("High connection-attempt volume")
            score += 20

        if failure_ratio >= 0.80 and attempts >= 5 and reasons:
            reasons.append("High connection-failure ratio")
            score += 10

        score = min(score, 100)

        if score >= 80:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "source_id": source_id,
            "window_end": latest.isoformat(),
            "attempts_10m": attempts,
            "unique_ports_60s": recent_ports,
            "unique_ports_10m": long_ports,
            "failure_ratio_10m": round(failure_ratio, 3),
            "score": score,
            "severity": severity,
            "status": "ALERT" if reasons else "NO_ALERT",
            "reasons": reasons,
        })

    return pd.DataFrame(results)
