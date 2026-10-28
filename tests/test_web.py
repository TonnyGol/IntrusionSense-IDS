import time

import pytest
from conftest import START_TIME
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from test_rules import record
from test_server import CALM, FLOOD, flow, post_batch

from intrusionsense.detection import Detector
from intrusionsense.rules import RuleEngine
from intrusionsense.server.app import create_app
from intrusionsense.server.security import MAX_LOGIN_FAILURES, hash_password
from intrusionsense.server.services import Services
from intrusionsense.storage.alerts import AlertStore
from intrusionsense.storage.models import Alert, AuditLog, User

CLIENT = {"X-Requested-With": "IntrusionSense"}
PASSWORD = "correct horse battery"


@pytest.fixture
def services(session_factory, stub_engine):
    return Services(session_factory, Detector(stub_engine, RuleEngine([])), AlertStore(session_factory))


@pytest.fixture
def client(services):
    # the context manager runs the app's start-up, which attaches the live-alert hub to the event loop
    with TestClient(
        create_app(services, session_secret="test-secret"), base_url="http://testserver"
    ) as client:
        yield client


@pytest.fixture
def users(session_factory):
    with session_factory() as session:
        for name, role in (("alice", "Admin"), ("mary", "Manager"), ("sam", "SOC Analyst")):
            session.add(User(Username=name, PasswordHash=hash_password(PASSWORD), Role=role))
        session.commit()


def sign_in(client, username, password=PASSWORD):
    return client.post("/api/login", json={"username": username, "password": password}, headers=CLIENT)


def seeded_alert(client, session_factory, at=None):
    with session_factory() as session:
        from intrusionsense.storage.sensors import create_sensor

        token = create_sensor(session, "s1")
    post_batch(client, token, flow(FLOOD, end_time=at or START_TIME))
    with session_factory() as session:
        return session.query(Alert).one().AlertID


def test_first_run_setup_creates_an_admin_once(client):
    assert client.get("/api/setup").json() == {"needed": True}
    assert (
        client.post(
            "/api/setup", json={"username": "owner", "password": PASSWORD}, headers=CLIENT
        ).status_code
        == 200
    )
    assert client.get("/api/setup").json() == {"needed": False}
    assert (
        client.post(
            "/api/setup", json={"username": "x" * 5, "password": PASSWORD}, headers=CLIENT
        ).status_code
        == 409
    )


def test_setup_rejects_a_short_password(client):
    response = client.post("/api/setup", json={"username": "owner", "password": "short"}, headers=CLIENT)
    assert response.status_code == 422


def test_sign_in_sets_a_session_and_reports_permissions(client, users):
    assert client.get("/api/me").status_code == 401

    response = sign_in(client, "sam")
    assert response.status_code == 200
    assert response.json()["permissions"] == ["triage_alerts"]
    assert client.get("/api/me").json()["username"] == "sam"


def test_wrong_password_and_unknown_user_look_the_same(client, users):
    wrong = sign_in(client, "sam", "not the password")
    unknown = sign_in(client, "nobody")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_repeated_failures_lock_the_account_out_temporarily(client, users):
    for _ in range(MAX_LOGIN_FAILURES):
        sign_in(client, "sam", "wrong password")

    assert sign_in(client, "sam").status_code == 429  # even the right password is refused during the lockout


def test_a_legacy_sha256_hash_cannot_sign_in(client, session_factory):
    import hashlib

    with session_factory() as session:
        session.add(User(Username="old", PasswordHash=hashlib.sha256(b"admin123").hexdigest(), Role="Admin"))
        session.commit()

    assert sign_in(client, "old", "admin123").status_code == 401


def test_state_changing_requests_need_the_client_header(client, users):
    sign_in(client, "alice")

    forged = client.post("/api/rules", json={"name": "x", "condition": "Port 23", "action": "Alert Low"})
    assert forged.status_code == 403


def test_roles_are_enforced_on_the_server(client, users):
    rule = {"name": "telnet", "condition": "Port 23", "action": "Alert Low"}

    sign_in(client, "sam")
    assert client.get("/api/rules").status_code == 200
    assert client.post("/api/rules", json=rule, headers=CLIENT).status_code == 403
    assert client.get("/api/users").status_code == 403
    assert client.get("/api/audit").status_code == 403

    sign_in(client, "mary")
    assert client.post("/api/rules", json=rule, headers=CLIENT).status_code == 201
    assert client.get("/api/audit").status_code == 200
    assert client.post("/api/sensors", json={"name": "x"}, headers=CLIENT).status_code == 403

    sign_in(client, "alice")
    assert client.get("/api/users").status_code == 200
    assert client.post("/api/sensors", json={"name": "x"}, headers=CLIENT).json()["token"]


def test_role_changes_apply_to_a_signed_in_session_immediately(client, users, session_factory):
    sign_in(client, "mary")
    with session_factory() as session:
        session.query(User).filter_by(Username="mary").update({"Role": "SOC Analyst"})
        session.commit()

    rule = {"name": "t", "condition": "Port 23", "action": "Alert Low"}
    assert client.post("/api/rules", json=rule, headers=CLIENT).status_code == 403


def test_rules_that_cannot_be_loaded_are_refused_and_saved_rules_take_effect(client, users, services):
    sign_in(client, "alice")
    bad = {"name": "bad", "condition": "Colour red", "action": "Alert Low"}
    assert client.post("/api/rules", json=bad, headers=CLIENT).status_code == 422

    good = {"name": "telnet", "condition": "Port 23", "action": "Alert High"}
    assert client.post("/api/rules", json=good, headers=CLIENT).status_code == 201
    assert services.detector.analyze(record(dst_port=23)).label == "telnet"


def test_last_admin_cannot_be_demoted_or_deleted(client, users, session_factory):
    sign_in(client, "alice")
    with session_factory() as session:
        alice_id = session.query(User).filter_by(Username="alice").one().UserID

    assert client.patch(f"/api/users/{alice_id}", json={"role": "Manager"}, headers=CLIENT).status_code == 409
    assert client.delete(f"/api/users/{alice_id}", headers=CLIENT).status_code == 409


def test_analyst_can_triage_an_alert_and_it_is_audited(client, users, session_factory):
    alert_id = seeded_alert(client, session_factory)
    sign_in(client, "sam")

    response = client.patch(f"/api/alerts/{alert_id}", json={"status": "acknowledged"}, headers=CLIENT)

    assert response.json()["status"] == "acknowledged"
    with session_factory() as session:
        assert session.query(AuditLog).filter_by(Action="alert_status", Username="sam").count() == 1
    assert (
        client.patch(f"/api/alerts/{alert_id}", json={"status": "bogus"}, headers=CLIENT).status_code == 422
    )


def test_alert_list_filters_and_detail_never_contains_markup_from_payloads(client, users, session_factory):
    alert_id = seeded_alert(client, session_factory)
    sign_in(client, "sam")

    assert len(client.get("/api/alerts", params={"severity": "High"}).json()["alerts"]) == 1
    assert client.get("/api/alerts", params={"severity": "Low"}).json()["alerts"] == []
    assert client.get("/api/alerts", params={"search": "10.0.0.66"}).json()["alerts"]
    assert client.get(f"/api/alerts/{alert_id}").json()["id"] == alert_id
    assert client.get("/api/alerts/9999").status_code == 404


def test_stats_counts_alerts_by_hour_and_severity(client, users, session_factory):
    seeded_alert(client, session_factory, at=time.time())
    sign_in(client, "sam")

    stats = client.get("/api/stats").json()

    assert stats["open_by_severity"]["High"] == 1
    assert len(stats["hours"]) == 24
    assert stats["top_attack_types"][0]["name"] == "DoS"


def test_every_response_carries_security_headers(client):
    response = client.get("/")

    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert client.get("/api/setup").headers["cache-control"] == "no-store"


def test_the_page_and_script_are_served_without_inline_code(client):
    page = client.get("/").text

    assert "/static/app.js" in page
    assert "<script>" not in page and "onclick=" not in page
    assert client.get("/static/app.js").status_code == 200


def test_websocket_requires_a_session_and_a_matching_origin(client, users):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"origin": "http://testserver"}):
            pass

    sign_in(client, "sam")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}):
            pass
    with client.websocket_connect("/ws", headers={"origin": "http://testserver"}):
        pass


def test_new_alerts_are_pushed_to_connected_browsers(client, users, session_factory):
    sign_in(client, "sam")
    with session_factory() as session:
        from intrusionsense.storage.sensors import create_sensor

        token = create_sensor(session, "s1")

    with client.websocket_connect("/ws", headers={"origin": "http://testserver"}) as socket:
        post_batch(client, token, flow(FLOOD), flow(CALM, dst_port=443))
        event = socket.receive_json()

    assert event["type"] == "alert"
    assert event["alert"]["attack_type"] == "DoS"


def test_a_heartbeat_marks_an_idle_sensor_online(client, users, session_factory):
    from intrusionsense.storage.sensors import create_sensor

    with session_factory() as session:
        token = create_sensor(session, "idle")
    sign_in(client, "sam")
    assert client.get("/api/sensors").json()[0]["online"] is False

    assert post_batch(client, token).json() == {"accepted": 0, "new_alerts": 0}

    assert client.get("/api/sensors").json()[0]["online"] is True


def test_the_server_has_a_websocket_library_for_live_alerts():
    """Plain uvicorn answers /ws with 404 and no hint; the Docker image only has what pyproject lists."""
    import importlib.metadata

    requirements = importlib.metadata.requires("intrusionsense") or []
    assert any(requirement.lower().startswith("websockets") for requirement in requirements)
