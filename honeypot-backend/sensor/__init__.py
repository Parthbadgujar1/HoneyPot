"""
AI-adaptive honeypot sensor.

Runs decoy services (SSH, HTTP, banner-grabbing bait ports), records
telemetry to a local SQLite store, scores reconnaissance behaviour with
rules plus the trained ML models, adapts decoy responses per attacker,
and optionally blocks attacker IPs through Windows Defender Firewall.
"""
