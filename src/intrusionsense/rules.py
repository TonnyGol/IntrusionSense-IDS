"""User-defined detection rules, stored in the DB as "<field> <value>" condition text."""

import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import StrEnum

from intrusionsense.labels import Severity
from intrusionsense.packets import protocol_name
from intrusionsense.records import FlowRecord

log = logging.getLogger(__name__)

PORT_SCAN_WINDOW_SECONDS = 10.0
DEST_PORT_WINDOW_SECONDS = 10.0
PRUNE_EVERY_N_RECORDS = 10_000


class RuleField(StrEnum):
    SOURCE_IP = "Source IP"
    DEST_IP = "Dest IP"
    PORT = "Port"
    PROTOCOL = "Protocol"
    PACKET_COUNT = "Packet Count"
    PAYLOAD_REGEX = "Payload Regex"
    CONNECTIONS_PER_MINUTE = "Connection Attempts / min"
    UNIQUE_PORTS_PER_10S = "Unique Ports Scanned / 10s"
    # counts analysed flows to the port, not single packets; the label is kept for saved rules
    PACKETS_TO_DEST_PORT_PER_10S = "Packets to Dest Port / 10s"


THRESHOLD_FIELDS = {
    RuleField.PACKET_COUNT,
    RuleField.CONNECTIONS_PER_MINUTE,
    RuleField.UNIQUE_PORTS_PER_10S,
    RuleField.PACKETS_TO_DEST_PORT_PER_10S,
}


class RuleAction(StrEnum):
    ALERT_HIGH = "Alert High"
    ALERT_MEDIUM = "Alert Medium"
    ALERT_LOW = "Alert Low"
    # suppresses matching traffic; nothing is blocked
    IGNORE = "Ignore (allowlist)"


# "Drop / Block" is the old name of IGNORE: it never blocked anything
LEGACY_ACTION_NAMES = {"Drop / Block": RuleAction.IGNORE}

SEVERITY_BY_ACTION = {
    RuleAction.ALERT_HIGH: Severity.HIGH,
    RuleAction.ALERT_MEDIUM: Severity.MEDIUM,
    RuleAction.ALERT_LOW: Severity.LOW,
}


@dataclass(frozen=True)
class Rule:
    rule_id: int | None
    name: str
    field: RuleField
    value: str
    action: RuleAction
    threshold: int | None = None
    pattern: re.Pattern | None = None

    @property
    def severity(self) -> Severity | None:
        return SEVERITY_BY_ACTION.get(self.action)


def parse_rule(rule_id: int | None, name: str, condition_text: str, action_name: str) -> Rule | None:
    """DB row -> Rule, or None (logged) when the row cannot be used."""
    text = (condition_text or "").strip()
    rule_field = next((f for f in RuleField if text.startswith(f.value)), None)
    try:
        action = LEGACY_ACTION_NAMES.get(action_name) or RuleAction(action_name)
    except ValueError:
        action = None
    if rule_field is None or action is None:
        log.warning(
            "Skipping rule %s %r: unknown field or action in %r / %r", rule_id, name, text, action_name
        )
        return None

    value = text[len(rule_field.value) :].strip()
    threshold = pattern = None
    try:
        if rule_field in THRESHOLD_FIELDS:
            threshold = int(value)
        elif rule_field is RuleField.PAYLOAD_REGEX:
            pattern = re.compile(value)
    except (ValueError, re.error) as exc:
        log.warning("Skipping rule %s %r: bad value %r (%s)", rule_id, name, value, exc)
        return None
    return Rule(rule_id, name or "Custom Rule", rule_field, value, action, threshold, pattern)


class RuleEngine:
    """Matches flow records against rules. Rate windows use capture time, so pcap replay behaves like live."""

    def __init__(self, rules: list[Rule]):
        self.ignore_rules = [rule for rule in rules if rule.action is RuleAction.IGNORE]
        self.alert_rules = [rule for rule in rules if rule.action is not RuleAction.IGNORE]
        self._ports_probed: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._flows_to_port: dict[tuple[str, int], deque[float]] = defaultdict(deque)
        self._records_since_prune = 0

    def is_ignored(self, record: FlowRecord) -> bool:
        return any(self._matches_identity(rule, record) for rule in self.ignore_rules)

    def match(self, record: FlowRecord) -> Rule | None:
        self._prune_quiet_windows(record.end_time)
        unique_ports = self._track_port_probe(record)
        flows_to_port = self._track_flow_to_port(record)
        for rule in self.alert_rules:
            if self._matches(rule, record, unique_ports, flows_to_port):
                return rule
        return None

    @staticmethod
    def _matches_identity(rule: Rule, record: FlowRecord) -> bool:
        match rule.field:
            case RuleField.SOURCE_IP:
                return rule.value == str(record.src_ip)
            case RuleField.DEST_IP:
                return rule.value == str(record.dst_ip)
            case RuleField.PORT:
                return rule.value in (str(record.src_port), str(record.dst_port))
            case RuleField.PROTOCOL:
                return rule.value.upper() == protocol_name(record.protocol)
        return False

    def _matches(self, rule: Rule, record: FlowRecord, unique_ports: int, flows_to_port: int) -> bool:
        match rule.field:
            case RuleField.PACKET_COUNT:
                return record.packet_count >= rule.threshold
            case RuleField.PAYLOAD_REGEX:
                return any(
                    rule.pattern.search(payload.decode("utf-8", errors="ignore"))
                    for payload in record.payload_samples
                )
            case RuleField.CONNECTIONS_PER_MINUTE:
                return record.src_connections_last_minute >= rule.threshold
            case RuleField.UNIQUE_PORTS_PER_10S:
                return unique_ports >= rule.threshold
            case RuleField.PACKETS_TO_DEST_PORT_PER_10S:
                return flows_to_port >= rule.threshold
        return self._matches_identity(rule, record)

    def _prune_quiet_windows(self, now: float) -> None:
        """Forget address pairs with nothing inside their window, so memory stays bounded."""
        self._records_since_prune += 1
        if self._records_since_prune < PRUNE_EVERY_N_RECORDS:
            return
        self._records_since_prune = 0
        for pair, probes in list(self._ports_probed.items()):
            if probes[-1][0] < now - PORT_SCAN_WINDOW_SECONDS:
                del self._ports_probed[pair]
        for target, seen in list(self._flows_to_port.items()):
            if seen[-1] < now - DEST_PORT_WINDOW_SECONDS:
                del self._flows_to_port[target]

    def _track_port_probe(self, record: FlowRecord) -> int:
        probes = self._ports_probed[(str(record.src_ip), str(record.dst_ip))]
        probes.append((record.end_time, record.dst_port))
        _drop_older_than(probes, record.end_time - PORT_SCAN_WINDOW_SECONDS, key=lambda probe: probe[0])
        return len({port for _, port in probes})

    def _track_flow_to_port(self, record: FlowRecord) -> int:
        seen = self._flows_to_port[(str(record.dst_ip), record.dst_port)]
        seen.append(record.end_time)
        _drop_older_than(seen, record.end_time - DEST_PORT_WINDOW_SECONDS, key=lambda timestamp: timestamp)
        return len(seen)


def _drop_older_than(window: deque, cutoff: float, key) -> None:
    while window and key(window[0]) < cutoff:
        window.popleft()
