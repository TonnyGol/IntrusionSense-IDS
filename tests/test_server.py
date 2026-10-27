import pytest
from conftest import START_TIME
from fastapi.testclient import TestClient
from test_rules import record

from intrusionsense.detection import Detector
from intrusionsense.records import FlowBatch
from intrusionsense.rules import RuleEngine
from intrusionsense.server.app import MAX_BATCH_BYTES, SENSOR_INGEST_PATH, create_app
from intrusionsense.server.services import Services
from intrusionsense.storage.alerts import AlertStore
from intrusionsense.storage.models import Alert, Rule, Sensor
from intrusionsense.storage.sensors import create_sensor

FLOOD = {"Flow Packets/s": 800.0, "Total Fwd Packets": 70.0}
CALM = {"Flow Packets/s": 2.0, "Total Fwd Packets": 1.0}


@pytest.fixture
def services(session_factory, stub_engine):
    return Services(session_factory, Detector(stub_engine, RuleEngine([])), AlertStore(session_factory))


@pytest.fixture
def client(services):
    return TestClient(create_app(services))


@pytest.fixture
def token(session_factory):
    with session_factory() as session:
        return create_sensor(session, "test-sensor")


def post_batch(client, token, *records):
    body = FlowBatch(records=list(records)).model_dump_json()
    return client.post(
        SENSOR_INGEST_PATH,
        content=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )


def flow(features, **overrides):
    return record(**overrides).model_copy(update={"features": features})


def test_health_reports_ok_when_the_database_answers(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_ingest_requires_a_valid_sensor_token(client):
    assert post_batch(client, "", flow(FLOOD)).status_code == 401
    assert post_batch(client, "not-a-real-token", flow(FLOOD)).status_code == 401


def test_revoked_sensor_is_refused(client, token, session_factory):
    with session_factory() as session:
        session.query(Sensor).update({"IsActive": False})
        session.commit()

    assert post_batch(client, token, flow(FLOOD)).status_code == 401


def test_oversized_batch_is_refused_before_parsing(client, token):
    response = client.post(
        SENSOR_INGEST_PATH,
        content=b"x" * (MAX_BATCH_BYTES + 1),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 413


def test_attack_flow_becomes_a_stored_alert(client, token, session_factory):
    response = post_batch(client, token, flow(FLOOD), flow(CALM, dst_port=443))

    assert response.json() == {"accepted": 2, "new_alerts": 1}
    with session_factory() as session:
        [alert] = session.query(Alert).all()
        assert (alert.AttackType, alert.Detection, alert.Severity) == ("DoS", "model", "High")
        assert alert.associated_log.DstPort == 80
        assert alert.sensor.Name == "test-sensor"


def test_repeats_inside_the_window_fold_into_one_alert(client, token, session_factory):
    post_batch(client, token, *[flow(FLOOD, end_time=START_TIME + i) for i in range(5)])

    with session_factory() as session:
        [alert] = session.query(Alert).all()
        assert alert.RepeatCount == 5


def test_rule_match_is_stored_without_a_confidence(services, client, token, session_factory):
    with session_factory() as session:
        session.add(Rule(RuleName="telnet", ConditionText="Port 23", Severity="Alert Low"))
        session.commit()
    services.reload_rules()

    post_batch(client, token, flow(CALM, dst_port=23))

    with session_factory() as session:
        [alert] = session.query(Alert).all()
        assert (alert.AttackType, alert.Detection, alert.Confidence, alert.Severity) == (
            "telnet",
            "rule",
            None,
            "Low",
        )


def test_invalid_records_are_rejected(client, token):
    response = client.post(
        SENSOR_INGEST_PATH,
        content='{"records":[{"src_ip":"not-an-ip"}]}',
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    assert response.status_code == 422
