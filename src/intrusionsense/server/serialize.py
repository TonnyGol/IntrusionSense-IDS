import base64
import json
from datetime import datetime

from intrusionsense.storage.models import Alert, Rule, Sensor

MAX_PAYLOAD_PREVIEW_CHARS = 600
PRINTABLE_ASCII = range(0x20, 0x7F)
SENSOR_ONLINE_SECONDS = 120.0


def iso_utc(moment: datetime | None) -> str | None:
    # DB timestamps are naive UTC; the Z lets the browser convert to local time
    return moment.isoformat(timespec="seconds") + "Z" if moment else None


def payload_preview(raw: bytes) -> str:
    """Printable text for display; every other byte becomes '.' so no markup or control codes get through."""
    text = "".join(chr(b) if b in PRINTABLE_ASCII or b in (0x0A, 0x0D) else "." for b in raw)
    return text[:MAX_PAYLOAD_PREVIEW_CHARS]


def alert_to_dict(alert: Alert, with_payloads: bool = False) -> dict:
    log = alert.associated_log
    data = {
        "id": alert.AlertID,
        "time": iso_utc(alert.Timestamp),
        "last_seen": iso_utc(alert.LastSeenAt),
        "repeat_count": alert.RepeatCount,
        "severity": alert.Severity,
        "attack_type": alert.AttackType,
        "detection": alert.Detection,
        "confidence": alert.Confidence,
        "layer": alert.Layer,
        "error": alert.Error,
        "status": alert.Status,
        "src_ip": log.SourceIP,
        "dst_ip": log.DestIP,
        "src_port": log.SrcPort,
        "dst_port": log.DstPort,
        "protocol": log.Protocol,
        "packet_count": log.PacketCount,
        "avg_packet_size": log.PacketSize,
        "sensor": alert.sensor.Name if alert.sensor else None,
        "rule": alert.triggered_rule.RuleName if alert.triggered_rule else None,
    }
    if with_payloads:
        samples = json.loads(alert.PayloadSamples or "[]")
        data["payloads"] = [payload_preview(base64.b64decode(s)) for s in samples]
    return data


def rule_to_dict(rule: Rule) -> dict:
    return {
        "id": rule.RuleID,
        "name": rule.RuleName,
        "description": rule.Description,
        "condition": rule.ConditionText,
        "action": rule.Severity,
        "active": bool(rule.IsActive),
    }


def sensor_to_dict(sensor: Sensor, now: datetime) -> dict:
    seen = sensor.LastSeenAt
    return {
        "id": sensor.SensorID,
        "name": sensor.Name,
        "active": bool(sensor.IsActive),
        "created": iso_utc(sensor.CreatedAt),
        "last_seen": iso_utc(seen),
        "online": bool(sensor.IsActive and seen and (now - seen).total_seconds() < SENSOR_ONLINE_SECONDS),
    }
