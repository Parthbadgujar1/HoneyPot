import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


def _login(client, username="admin", password="admin123"):
    r = client.post(
        "/api/auth/login",
        data={"username": username, "password": password},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_and_me(client):
    token = _login(client)
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "admin"
    assert r.json()["role"] == "ADMIN"


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", data={"username": "admin", "password": "bad"})
    assert r.status_code == 401


def test_rbac_viewer_cannot_train_models(client):
    token = _login(client, "viewer", "viewer123")
    r = client.post("/api/models/train", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_unauthorized_access_rejected(client):
    r = client.get("/api/dashboard/summary")
    assert r.status_code in (401, 403)


def test_simulate_ingests_events(client):
    token = _login(client)
    h = {"Authorization": f"Bearer {token}"}
    before = client.get("/api/dashboard/summary", headers=h).json()
    r = client.post(
        "/api/honeypot/simulate?scenario=benign&n_sessions=1", headers=h
    )
    assert r.status_code == 200, r.text
    after = client.get("/api/dashboard/summary", headers=h).json()
    assert after["total_sessions"] >= before["total_sessions"]
    assert after["total_events"] >= before["total_events"]


def test_unknown_scenario_rejected(client):
    token = _login(client)
    r = client.post(
        "/api/honeypot/simulate?scenario=nope&n_sessions=1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 400


def test_honeypot_status(client):
    token = _login(client)
    r = client.get(
        "/api/honeypot/status", headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200
    data = r.json()
    assert data["adapter"]["online"] is True
    assert "collector" in data
