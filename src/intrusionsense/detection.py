import threading
from dataclasses import dataclass
from enum import StrEnum

from intrusionsense.engine import IDSEngine
from intrusionsense.labels import ENGINE_ERROR_LABEL, Severity, severity_for_label
from intrusionsense.records import FlowRecord
from intrusionsense.rules import RuleEngine


class DetectionSource(StrEnum):
    RULE = "rule"
    MODEL = "model"
    ENGINE_ERROR = "engine_error"


@dataclass(frozen=True)
class Detection:
    record: FlowRecord
    label: str
    severity: Severity
    source: DetectionSource
    confidence: float | None = None  # model probability; None for rule matches
    layer: int | None = None
    rule_id: int | None = None
    error: str | None = None


class Detector:
    """Decides whether a flow record is an attack: ignore rules, then alert rules, then the ML engine."""

    def __init__(self, engine: IDSEngine, rule_engine: RuleEngine):
        self.engine = engine
        self._rule_engine = rule_engine
        # rule windows are mutable state and the web server handles batches on several threads
        self._lock = threading.Lock()

    def replace_rules(self, rule_engine: RuleEngine) -> None:
        with self._lock:
            self._rule_engine = rule_engine

    def analyze(self, record: FlowRecord) -> Detection | None:
        with self._lock:
            if self._rule_engine.is_ignored(record):
                return None
            rule = self._rule_engine.match(record)
        if rule is not None:
            return Detection(record, rule.name, rule.severity, DetectionSource.RULE, rule_id=rule.rule_id)

        verdict = self.engine.predict(record.features)
        if not verdict.is_threat:
            return None
        source = (
            DetectionSource.ENGINE_ERROR if verdict.label == ENGINE_ERROR_LABEL else DetectionSource.MODEL
        )
        return Detection(
            record,
            verdict.label,
            severity_for_label(verdict.label),
            source,
            confidence=verdict.confidence,
            layer=verdict.layer,
            error=verdict.error,
        )
