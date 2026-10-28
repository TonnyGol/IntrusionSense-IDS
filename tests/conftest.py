import joblib
import numpy as np
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from sklearn.tree import DecisionTreeClassifier
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from intrusionsense.engine import IDSEngine
from intrusionsense.packets import parse_packet
from intrusionsense.storage.db import init_db

ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.10"
START_TIME = 1_700_000_000.0
STUB_FEATURES = ["Flow Packets/s", "Total Fwd Packets"]


def tcp_packet(src=ATTACKER, dst=VICTIM, sport=40000, dport=80, flags="S", payload=b"", at=START_TIME):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        packet = packet / Raw(load=payload)
    packet.time = at
    return packet


def udp_packet(src=ATTACKER, dst=VICTIM, sport=5353, dport=53, payload=b"q", at=START_TIME):
    packet = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=payload)
    packet.time = at
    return packet


def info(packet):
    return parse_packet(packet)


@pytest.fixture
def session_factory():
    # one shared in-memory database for every session the code under test opens
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    return init_db(engine)


@pytest.fixture
def stub_model_dir(tmp_path):
    """Tiny models in the real file layout: suspicious when Flow Packets/s is high; Layer 2 says DoS."""
    rows = np.array([[1, 1], [5, 2], [500, 50], [900, 80]], dtype=float)
    layer1 = DecisionTreeClassifier(random_state=0).fit(rows, [0, 0, 1, 1])
    layer2 = DecisionTreeClassifier(random_state=0).fit(rows, [4, 4, 3, 3])
    joblib.dump(layer1, tmp_path / "layer1_model.pkl")
    joblib.dump(STUB_FEATURES, tmp_path / "layer1_features.pkl")
    joblib.dump(layer2, tmp_path / "layer2_model.pkl")
    joblib.dump(STUB_FEATURES, tmp_path / "layer2_features.pkl")
    return tmp_path


@pytest.fixture
def stub_engine(stub_model_dir):
    return IDSEngine(stub_model_dir, l1_threshold=0.5)
