"""Runs a throwaway IntrusionSense server on SQLite with sample alerts, for the README screenshots and GIF.

Run from the repo root:  python scripts/demo/serve_demo.py
Then, in a second terminal: cd scripts/demo && npm install && npm run record

Everything shown is sample data. Attackers use the documentation address ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), which are never routed on the internet.
"""

import base64
import json
import sys
import threading
import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from intrusionsense.config import ServerSettings
from intrusionsense.detection import Detection, DetectionSource
from intrusionsense.flows import FlowEvent
from intrusionsense.labels import severity_for_label
from intrusionsense.records import FlowRecord
from intrusionsense.server.app import create_app
from intrusionsense.server.security import hash_password
from intrusionsense.server.services import build_services
from intrusionsense.storage.db import init_db
from intrusionsense.storage.models import Alert, Rule, Sensor, User
from intrusionsense.storage.sensors import authenticate_sensor, create_sensor

DEMO_DIR = Path(__file__).resolve().parent / ".demo"
HOST, PORT = "127.0.0.1", 8765
ADMIN_USER, ADMIN_PASSWORD = "admin", "demo-password-123"
SESSION_SECRET = "demo-only-session-secret-not-used-anywhere-else"
HEARTBEAT_SECONDS = 20  # sensors count as online for 120 s after they were last heard from
PROTOCOL_TCP = 6
WEB_SERVER, DB_SERVER, LAPTOP = "10.0.0.10", "10.0.0.20", "10.0.0.31"

# (minutes ago, label, attacker, target, target port, how it was found, confidence, repeats, status)
MODEL, RULE = DetectionSource.MODEL, DetectionSource.RULE
SAMPLE_ALERTS = [
    (1380, "DoS", "198.51.100.23", WEB_SERVER, 80, MODEL, 0.97, 41, "resolved"),
    (1290, "Port scan", "192.0.2.14", DB_SERVER, 3306, RULE, None, 3, "resolved"),
    (1110, "Brute Force", "203.0.113.9", WEB_SERVER, 22, MODEL, 0.93, 12, "acknowledged"),
    (930, "Web attack signature", "192.0.2.88", WEB_SERVER, 80, RULE, None, 5, "false_positive"),
    (840, "Port Scanning", "192.0.2.14", LAPTOP, 445, MODEL, 0.88, 2, "acknowledged"),
    (700, "Bots", "203.0.113.77", LAPTOP, 8080, MODEL, 0.91, 7, "active"),
    (610, "Connection flood", "198.51.100.5", WEB_SERVER, 443, RULE, None, 18, "resolved"),
    (520, "DDoS", "198.51.100.40", WEB_SERVER, 80, MODEL, 0.99, 63, "active"),
    (455, "DDoS", "198.51.100.41", WEB_SERVER, 80, MODEL, 0.98, 58, "active"),
    (330, "Web Attacks", "192.0.2.88", WEB_SERVER, 80, MODEL, 0.82, 4, "active"),
    (250, "Brute Force", "203.0.113.9", WEB_SERVER, 22, MODEL, 0.95, 21, "active"),
    (180, "Port scan", "192.0.2.201", DB_SERVER, 5432, RULE, None, 2, "active"),
    (95, "Web attack signature", "192.0.2.66", WEB_SERVER, 80, RULE, None, 3, "active"),
    (60, "DoS", "198.51.100.23", WEB_SERVER, 80, MODEL, 0.96, 33, "active"),
    (42, "Port Scanning", "192.0.2.201", LAPTOP, 22, MODEL, 0.9, 2, "active"),
    (28, "Bots", "203.0.113.77", LAPTOP, 8080, MODEL, 0.87, 3, "active"),
    (14, "Connection flood", "198.51.100.5", WEB_SERVER, 443, RULE, None, 9, "active"),
]
SQL_INJECTION = b"GET /products?id=1' OR '1'='1 HTTP/1.1\r\nHost: shop.example\r\n\r\n"
PAYLOADS = {"Web attack signature": [SQL_INJECTION], "Web Attacks": [SQL_INJECTION]}


def seed(session_factory, services) -> dict:
    """Fill the database with users, sensors and alerts spread over the last 24 hours."""
    with session_factory() as session:
        for name, role in ((ADMIN_USER, "Admin"), ("maria.soc", "SOC Analyst"), ("dan.manager", "Manager")):
            session.add(User(Username=name, Email=f"{name}@example.com", Role=role,
                             PasswordHash=hash_password(ADMIN_PASSWORD)))
        tokens = {name: create_sensor(session, name) for name in ("web-server", "office-laptop")}
        rule_ids = {rule.RuleName: rule.RuleID for rule in session.query(Rule).all()}

    web_sensor_id = _sensor_id(session_factory, "web-server")
    now = time.time()
    for minutes_ago, label, attacker, target, port, source, confidence, repeats, status in SAMPLE_ALERTS:
        first = now - minutes_ago * 60
        for repeat in range(repeats):
            at = first + repeat * 5  # five seconds apart folds into one alert with a "seen" count
            record = FlowRecord(
                src_ip=attacker, dst_ip=target, src_port=40000 + repeat, dst_port=port,
                protocol=PROTOCOL_TCP, start_time=at - 2, end_time=at, packet_count=12,
                event=FlowEvent.FINISHED, features={"Packet Length Mean": 96},
                payload_samples=[base64.b64encode(p) for p in PAYLOADS.get(label, [])],  # base64 on the wire
            )
            detection = Detection(
                record, label, severity_for_label(label), source, confidence=confidence,
                layer=2 if source is MODEL else None, rule_id=rule_ids.get(label),
            )
            services.alert_store.save(detection, web_sensor_id)
        _set_status(session_factory, label, status)
    return tokens


def _sensor_id(session_factory, name: str) -> int:
    with session_factory() as session:
        return session.query(Sensor).filter_by(Name=name).one().SensorID


def _set_status(session_factory, label: str, status: str) -> None:
    if status == "active":
        return
    with session_factory() as session:
        alert = session.query(Alert).filter_by(AttackType=label).order_by(Alert.AlertID.desc()).first()
        alert.Status = status
        session.commit()


def keep_sensors_online(session_factory, tokens: dict) -> None:
    while True:
        with session_factory() as session:
            for token in tokens.values():
                authenticate_sensor(session, token)
        time.sleep(HEARTBEAT_SECONDS)


def main() -> None:
    import uvicorn

    DEMO_DIR.mkdir(exist_ok=True)
    database = DEMO_DIR / "demo.db"
    database.unlink(missing_ok=True)  # a fresh set of sample data every run
    engine = create_engine(f"sqlite:///{database}", connect_args={"check_same_thread": False})
    session_factory: sessionmaker = init_db(engine)
    settings = ServerSettings(db_password="unused-demo-uses-sqlite")
    services = build_services(settings, session_factory)
    tokens = seed(session_factory, services)

    (DEMO_DIR / "state.json").write_text(json.dumps({
        "url": f"http://{HOST}:{PORT}", "username": ADMIN_USER, "password": ADMIN_PASSWORD,
        "sensor_token": tokens["office-laptop"],
    }))
    threading.Thread(target=keep_sensors_online, args=(session_factory, tokens), daemon=True).start()
    print(f"Demo ready at http://{HOST}:{PORT}  (sign in as {ADMIN_USER}). Ctrl+C to stop.", flush=True)
    uvicorn.run(create_app(services, SESSION_SECRET), host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
