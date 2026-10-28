import math

import pytest
from conftest import ATTACKER, START_TIME, VICTIM, info, tcp_packet

from intrusionsense.config import DEFAULT_MODEL_DIR
from intrusionsense.engine import IDSEngine
from intrusionsense.features import compute_features
from intrusionsense.flows import FlowTable


def _http_exchange():
    """3-way handshake, a 100-byte request, a 300-byte reply, then FIN."""
    reply = {"src": VICTIM, "dst": ATTACKER, "sport": 80, "dport": 40000}
    packets = [
        tcp_packet(flags="S", at=START_TIME),
        tcp_packet(flags="SA", at=START_TIME + 0.010, **reply),
        tcp_packet(flags="A", at=START_TIME + 0.020),
        tcp_packet(flags="PA", payload=b"x" * 100, at=START_TIME + 0.030),
        tcp_packet(flags="PA", payload=b"y" * 300, at=START_TIME + 0.050, **reply),
        tcp_packet(flags="FA", at=START_TIME + 0.060),
    ]
    table = FlowTable()
    reports = [r for p in packets for r in table.add_packet(info(p))]
    [report] = reports
    return compute_features(report.flow)


def test_counts_lengths_and_duration():
    features = _http_exchange()

    assert features["Total Fwd Packets"] == 4
    assert features["Total Length of Fwd Packets"] == 100
    assert features["Fwd Packet Length Max"] == 100
    assert features["Bwd Packet Length Max"] == 300
    assert features["Flow Duration"] == pytest.approx(60_000)  # microseconds, first to last packet
    assert features["act_data_pkt_fwd"] == 1
    assert features["Flow Bytes/s"] == pytest.approx(400 / 0.06)


def test_flags_are_booleans_per_flow():
    features = _http_exchange()

    assert features["FIN Flag Count"] == 1
    assert features["PSH Flag Count"] == 1
    assert features["ACK Flag Count"] == 1


def test_idle_gap_longer_than_activity_timeout_is_recorded():
    table = FlowTable()
    table.add_packet(info(tcp_packet(flags="A", at=START_TIME)))
    table.add_packet(info(tcp_packet(flags="A", at=START_TIME + 1)))
    table.add_packet(info(tcp_packet(flags="A", at=START_TIME + 8)))  # 7 s gap > 5 s activity timeout
    [report] = table.close_all()

    features = compute_features(report.flow)
    assert features["Idle Max"] == pytest.approx(7_000_000)
    assert features["Active Max"] == pytest.approx(1_000_000)


def test_every_feature_the_real_models_expect_is_produced_and_finite():
    engine = IDSEngine(DEFAULT_MODEL_DIR, l1_threshold=0.2)
    features = _http_exchange()

    for name in set(engine.l1_features) | set(engine.l2_features):
        assert name in features
        assert math.isfinite(features[name])


def test_feature_names_constant_matches_what_compute_features_produces():
    from intrusionsense.features import FEATURE_NAMES

    assert list(_http_exchange()) == list(FEATURE_NAMES)
    assert len(FEATURE_NAMES) == 46
