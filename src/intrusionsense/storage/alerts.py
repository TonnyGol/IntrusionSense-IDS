import base64
import json
import threading

from sqlalchemy.orm import sessionmaker

from intrusionsense.detection import Detection
from intrusionsense.packets import protocol_name
from intrusionsense.storage.models import Alert, TrafficLog, utc_from_timestamp

# repeats of the same attacker -> target -> label inside this window update one alert instead of adding rows
REPEAT_WINDOW_SECONDS = 60.0
MAX_TRACKED_REPEAT_KEYS = 50_000

RepeatKey = tuple[str, str, str]  # src_ip, dst_ip, label


class AlertStore:
    """Writes detections to the DB, folding repeats of one attack into a single alert."""

    def __init__(self, session_factory: sessionmaker):
        self._session_factory = session_factory
        self._recent: dict[RepeatKey, tuple[int, float]] = {}  # key -> (alert id, last capture time)
        self._lock = threading.Lock()

    def save(self, detection: Detection, sensor_id: int | None) -> tuple[int, bool]:
        """Store the detection; returns (alert id, True if it is a new alert rather than a repeat)."""
        record = detection.record
        key = (str(record.src_ip), str(record.dst_ip), detection.label)
        with self._lock, self._session_factory() as session:
            recent = self._recent.get(key)
            if recent and record.end_time - recent[1] <= REPEAT_WINDOW_SECONDS:
                alert = session.get(Alert, recent[0])
                if alert is not None:
                    alert.RepeatCount += 1
                    alert.LastSeenAt = utc_from_timestamp(record.end_time)
                    session.commit()
                    self._recent[key] = (alert.AlertID, record.end_time)
                    return alert.AlertID, False

            alert = _new_alert(detection, sensor_id)
            session.add(alert)
            session.commit()
            self._remember(key, alert.AlertID, record.end_time)
            return alert.AlertID, True

    def _remember(self, key: RepeatKey, alert_id: int, capture_time: float) -> None:
        if len(self._recent) >= MAX_TRACKED_REPEAT_KEYS:
            cutoff = capture_time - REPEAT_WINDOW_SECONDS
            self._recent = {k: v for k, v in self._recent.items() if v[1] >= cutoff}
        self._recent[key] = (alert_id, capture_time)


def _new_alert(detection: Detection, sensor_id: int | None) -> Alert:
    record = detection.record
    mean_size = int(record.features.get("Packet Length Mean", 0))
    seen_at = utc_from_timestamp(record.end_time)
    log = TrafficLog(
        SourceIP=str(record.src_ip),
        DestIP=str(record.dst_ip),
        Protocol=protocol_name(record.protocol),
        SrcPort=record.src_port,
        DstPort=record.dst_port,
        PacketCount=record.packet_count,
        PacketSize=mean_size,
        CapturedAt=utc_from_timestamp(record.start_time),
    )
    return Alert(
        associated_log=log,
        TriggeredRuleID=detection.rule_id,
        SensorID=sensor_id,
        Timestamp=seen_at,
        LastSeenAt=seen_at,
        AttackType=detection.label,
        Severity=detection.severity.value,
        Detection=detection.source.value,
        Confidence=detection.confidence,
        Layer=detection.layer,
        Error=detection.error,
        PayloadSamples=json.dumps([base64.b64encode(p).decode("ascii") for p in record.payload_samples]),
    )
