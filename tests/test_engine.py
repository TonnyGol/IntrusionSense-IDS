from conftest import STUB_FEATURES

from intrusionsense.config import DEFAULT_MODEL_DIR
from intrusionsense.engine import NORMAL_LABEL, IDSEngine
from intrusionsense.labels import ATTACK_LABELS, ENGINE_ERROR_LABEL

CALM = {"Flow Packets/s": 2.0, "Total Fwd Packets": 1.0}
FLOOD = {"Flow Packets/s": 800.0, "Total Fwd Packets": 70.0}


def test_normal_traffic_stops_at_layer_1(stub_engine):
    verdict = stub_engine.predict(CALM)

    assert verdict.label == NORMAL_LABEL
    assert not verdict.is_threat
    assert verdict.layer == 1


def test_suspicious_traffic_gets_an_attack_label_from_layer_2(stub_engine):
    verdict = stub_engine.predict(FLOOD)

    assert verdict.label == "DoS"
    assert verdict.is_threat
    assert verdict.layer == 2
    assert 0 < verdict.confidence <= 1


def test_missing_feature_fails_closed(stub_engine):
    verdict = stub_engine.predict({STUB_FEATURES[0]: 800.0})

    assert verdict.label == ENGINE_ERROR_LABEL
    assert verdict.is_threat
    assert "missing" in verdict.error


def test_non_finite_feature_fails_closed(stub_engine):
    verdict = stub_engine.predict({**FLOOD, "Total Fwd Packets": float("nan")})

    assert verdict.label == ENGINE_ERROR_LABEL
    assert verdict.is_threat


def test_threshold_decides_what_reaches_layer_2(stub_model_dir):
    never_suspicious = IDSEngine(stub_model_dir, l1_threshold=1.0)

    assert not never_suspicious.predict(FLOOD).is_threat


def test_real_models_only_produce_known_labels():
    engine = IDSEngine(DEFAULT_MODEL_DIR, l1_threshold=0.0)  # send everything to Layer 2
    features = {name: 1.0 for name in engine.l2_features}

    verdict = engine.predict(features)
    assert verdict.label in ATTACK_LABELS.values()
