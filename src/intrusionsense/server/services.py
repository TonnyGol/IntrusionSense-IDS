from dataclasses import dataclass, field

from sqlalchemy.orm import sessionmaker

from intrusionsense.config import ServerSettings
from intrusionsense.detection import Detector
from intrusionsense.engine import IDSEngine
from intrusionsense.server.hub import AlertHub
from intrusionsense.server.security import LoginThrottle
from intrusionsense.storage.alerts import AlertStore
from intrusionsense.storage.db import create_db_engine, init_db, mysql_url
from intrusionsense.storage.rules import load_rule_engine, seed_default_rules


@dataclass
class Services:
    session_factory: sessionmaker
    detector: Detector
    alert_store: AlertStore
    hub: AlertHub = field(default_factory=AlertHub)
    login_throttle: LoginThrottle = field(default_factory=LoginThrottle)

    def reload_rules(self) -> None:
        with self.session_factory() as session:
            self.detector.replace_rules(load_rule_engine(session))


def build_services(settings: ServerSettings, session_factory: sessionmaker | None = None) -> Services:
    session_factory = session_factory or init_db(create_db_engine(mysql_url(settings)))
    with session_factory() as session:
        seed_default_rules(session)
        rule_engine = load_rule_engine(session)
    engine = IDSEngine(settings.model_dir, settings.l1_threshold)
    return Services(session_factory, Detector(engine, rule_engine), AlertStore(session_factory))
