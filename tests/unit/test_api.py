import asyncio
import json

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("argon2")
from fastapi.testclient import TestClient  # noqa: E402

from sih_api.app import create_app  # noqa: E402
from sih_api.auth import AuthStore  # noqa: E402
from sih_api.live import LiveHub  # noqa: E402
from sih_common.chttp import ClickHouseError  # noqa: E402

H = {"X-Requested-With": "sih-ui"}


class FakeCH:
    def __init__(self, up=True):
        self.up = up

    def ping(self):
        return self.up


class FakeQueries:
    def __init__(self, up=True):
        self.ch = FakeCH(up)
        self.up = up

    def incidents(self, *a):
        if not self.up:
            raise ClickHouseError("down", None, False)
        return [{"incident_id": "x", "explanation": "<script>alert(1)</script>"}]

    def stats(self, w):
        return {"window_minutes": w}

    def quarantine(self, limit):
        return []


@pytest.fixture
def client(tmp_path):
    auth = AuthStore({"admin": ("admin", "pw-admin-123"), "analyst": ("analyst", "pw-analyst-123")}, tmp_path / "audit.jsonl")
    app = create_app(auth=auth, queries=FakeQueries(), hub=LiveHub(), start_consumer=False, ui_dir=str(tmp_path / "noui"))
    return TestClient(app), tmp_path


def login(c, user, pw):
    return c.post("/api/login", json={"username": user, "password": pw}, headers=H)


def test_auth_roles_and_headers(client):
    c, tmp = client
    assert c.get("/api/incidents").status_code == 401
    assert login(c, "analyst", "wrong").status_code == 401
    assert c.post("/api/login", json={"username": "analyst", "password": "pw-analyst-123"}).status_code == 403  # no CSRF header
    r = login(c, "analyst", "pw-analyst-123")
    assert r.status_code == 200 and "httponly" in r.headers["set-cookie"].lower()
    r = c.get("/api/incidents")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.json()["items"][0]["explanation"] == "<script>alert(1)</script>"  # JSON data; the UI renders text only
    assert c.get("/api/quarantine").status_code == 403
    audit = [json.loads(line)["event"] for line in (tmp / "audit.jsonl").read_text().splitlines()]
    assert "login_failed" in audit and "login" in audit


def test_login_lockout(client):
    c, _ = client
    for _ in range(5):
        login(c, "admin", "nope")
    assert login(c, "admin", "pw-admin-123").status_code == 401


def test_history_outage_is_reported_not_hidden(tmp_path):
    auth = AuthStore({"a": ("analyst", "pw-analyst-123")}, tmp_path / "audit.jsonl")
    c = TestClient(create_app(auth=auth, queries=FakeQueries(up=False), hub=LiveHub(), start_consumer=False,
                              ui_dir=str(tmp_path / "noui")))
    login(c, "a", "pw-analyst-123")
    r = c.get("/api/incidents")
    assert r.status_code == 503 and r.json()["stale"] is True
    assert c.get("/api/ready").json()["status"] == "degraded"


def test_hub_resume_resync_and_slow_client():
    hub = LiveHub(ring_size=10, client_queue=2)

    async def scenario():
        hub.loop = asyncio.get_running_loop()
        alert = json.dumps({"status": "new", "evidence_received_at": "2026-09-11T10:00:00.000000Z"})
        q = hub.subscribe()
        for _ in range(4):
            hub.publish(alert)
        await asyncio.sleep(0.05)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        return items

    items = asyncio.run(scenario())
    assert None in items  # overflow sentinel -> resync
    backlog, resync = hub.backlog_after(f"{hub.nonce}-2")
    assert [s for s, _ in backlog] == [3, 4] and not resync
    assert hub.backlog_after("othernonce-1")[1] is True
    assert hub.latency_summary()["samples"] == 4
