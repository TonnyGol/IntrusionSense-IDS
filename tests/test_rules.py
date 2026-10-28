import base64

from conftest import ATTACKER, START_TIME, VICTIM

from intrusionsense.flows import FlowEvent
from intrusionsense.labels import Severity
from intrusionsense.records import FlowRecord
from intrusionsense.rules import RuleAction, RuleEngine, parse_rule


def record(dst_port=80, end_time=START_TIME, packets=2, payloads=(), connections=0, src=ATTACKER, protocol=6):
    return FlowRecord(
        src_ip=src,
        dst_ip=VICTIM,
        src_port=40000,
        dst_port=dst_port,
        protocol=protocol,
        start_time=end_time,
        end_time=end_time,
        packet_count=packets,
        event=FlowEvent.FINISHED,
        features={},
        payload_samples=[base64.b64encode(p) for p in payloads],
        src_connections_last_minute=connections,
    )


def engine(*rules):
    return RuleEngine(
        [parse_rule(i, name, condition, action) for i, (name, condition, action) in enumerate(rules)]
    )


def test_parse_reads_field_value_and_severity():
    rule = parse_rule(7, "Block telnet", "Port 23", "Alert High")

    assert (rule.field.value, rule.value, rule.severity) == ("Port", "23", Severity.HIGH)


def test_legacy_drop_block_action_loads_as_ignore():
    assert parse_rule(1, "old", "Source IP 1.2.3.4", "Drop / Block").action is RuleAction.IGNORE


def test_unusable_rows_are_skipped():
    assert parse_rule(1, "bad field", "Colour red", "Alert High") is None
    assert parse_rule(2, "bad action", "Port 23", "Explode") is None
    assert parse_rule(3, "bad number", "Packet Count lots", "Alert Low") is None
    assert parse_rule(4, "bad regex", "Payload Regex ([", "Alert Low") is None


def test_ignore_rules_suppress_matching_traffic_only():
    rules = engine(("trusted", f"Source IP {ATTACKER}", "Ignore (allowlist)"))

    assert rules.is_ignored(record())
    assert not rules.is_ignored(record(src="10.9.9.9"))


def test_identity_and_threshold_rules_match():
    rules = engine(("telnet", "Port 23", "Alert High"), ("big", "Packet Count 100", "Alert Low"))

    assert rules.match(record(dst_port=23)).name == "telnet"
    assert rules.match(record(packets=150)).name == "big"
    assert rules.match(record(packets=5)) is None


def test_payload_regex_searches_payload_samples():
    rules = engine(("sqli", r"Payload Regex (?i)union\s+select", "Alert Medium"))

    assert rules.match(record(payloads=[b"GET /?id=1 UNION SELECT pass"])).name == "sqli"
    assert rules.match(record(payloads=[b"GET /index.html"])) is None


def test_connection_rate_uses_the_sensors_count():
    rules = engine(("brute", "Connection Attempts / min 20", "Alert High"))

    assert rules.match(record(connections=25)) is not None
    assert rules.match(record(connections=3)) is None


def test_unique_ports_window_detects_a_scan_and_forgets_old_probes():
    rules = engine(("scan", "Unique Ports Scanned / 10s 5", "Alert Medium"))

    hits = [rules.match(record(dst_port=port, end_time=START_TIME + port * 0.1)) for port in range(1, 6)]
    assert hits[-1] is not None and hits[0] is None

    late = rules.match(record(dst_port=99, end_time=START_TIME + 60))
    assert late is None  # the earlier probes left the 10 s window


def test_default_rules_all_parse_and_the_web_signature_matches_attacks_only():
    from intrusionsense.storage.rules import DEFAULT_RULES

    parsed = [
        parse_rule(i, name, condition, action) for i, (name, _, condition, action) in enumerate(DEFAULT_RULES)
    ]
    assert all(rule is not None for rule in parsed)

    rules = RuleEngine([rule for rule in parsed if rule.field.value == "Payload Regex"])
    for attack in (b"id=1 UNION ALL SELECT pw", b"q=<script>alert(1)</script>", b"GET /../../etc/passwd"):
        assert rules.match(record(payloads=[attack])) is not None
    assert rules.match(record(payloads=[b"GET /search?q=select+a+union+card HTTP/1.1"])) is None
