import logging
import warnings
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

from intrusionsense.labels import ATTACK_LABELS, ENGINE_ERROR_LABEL

log = logging.getLogger(__name__)

NORMAL_LABEL = "Normal Traffic"
SUSPICIOUS_CLASS_INDEX = 1  # Layer 1 predict_proba column for "suspicious"
LAYER_1_FILES = ("layer1_model.pkl", "layer1_features.pkl")
LAYER_2_FILES = ("layer2_model.pkl", "layer2_features.pkl")


@dataclass(frozen=True, slots=True)
class Verdict:
    label: str
    is_threat: bool
    confidence: float | None
    layer: int
    error: str | None = None


def _load_layer(model_dir: Path, file_names: tuple[str, str]):
    model_file, features_file = (model_dir / name for name in file_names)
    model = joblib.load(model_file)
    features = list(joblib.load(features_file))
    log.info("Loaded %s (%d features)", model_file.name, len(features))
    return model, features


def _vectorize(features: dict[str, float], expected: list[str]) -> np.ndarray:
    """Feature dict -> 1-row array in model order. A missing or non-finite value is a bug, not a 0."""
    missing = [name for name in expected if name not in features]
    if missing:
        raise ValueError(f"missing features: {missing}")
    row = np.array([features[name] for name in expected], dtype=np.float64)
    if not np.isfinite(row).all():
        bad = [name for name, value in zip(expected, row, strict=True) if not np.isfinite(value)]
        raise ValueError(f"non-finite features: {bad}")
    return row.reshape(1, -1)


def _engine_error(layer: int, exc: Exception) -> Verdict:
    # fail closed: a flow the engine could not judge is reported, never silently marked safe
    log.error("Layer %d inference failed: %s", layer, exc)
    return Verdict(ENGINE_ERROR_LABEL, is_threat=True, confidence=None, layer=layer, error=str(exc))


class IDSEngine:
    """Two-stage classifier: Layer 1 triage (normal vs suspicious), Layer 2 attack type."""

    def __init__(self, model_dir: Path, l1_threshold: float):
        self.l1_threshold = l1_threshold
        self.l1_model, self.l1_features = _load_layer(model_dir, LAYER_1_FILES)
        self.l2_model, self.l2_features = _load_layer(model_dir, LAYER_2_FILES)

    def predict(self, features: dict[str, float]) -> Verdict:
        # models were fitted on a DataFrame; rows arrive as arrays in the same column order
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="X does not have valid feature names")
            return self._predict(features)

    def _predict(self, features: dict[str, float]) -> Verdict:
        try:
            suspicious_probability = self._suspicious_probability(features)
        except Exception as exc:
            return _engine_error(1, exc)
        if suspicious_probability <= self.l1_threshold:
            return Verdict(NORMAL_LABEL, is_threat=False, confidence=1 - suspicious_probability, layer=1)

        try:
            return self._classify_attack(features)
        except Exception as exc:
            return _engine_error(2, exc)

    def _suspicious_probability(self, features: dict[str, float]) -> float:
        row = _vectorize(features, self.l1_features)
        probabilities = self.l1_model.predict_proba(row)[0]
        return float(probabilities[SUSPICIOUS_CLASS_INDEX]) if len(probabilities) > 1 else 0.0

    def _classify_attack(self, features: dict[str, float]) -> Verdict:
        row = _vectorize(features, self.l2_features)
        probabilities = self.l2_model.predict_proba(row)[0]
        best = int(np.argmax(probabilities))
        predicted_class = self.l2_model.classes_[best]
        # classes_ holds either the integer ids in ATTACK_LABELS or the label strings themselves
        if isinstance(predicted_class, int | np.integer):
            label = ATTACK_LABELS.get(int(predicted_class))
            if label is None:
                raise ValueError(f"unknown Layer 2 class id: {predicted_class}")
        else:
            label = str(predicted_class)
        # Layer 2 only sees suspicious flows and every class it knows is an attack
        return Verdict(label, is_threat=True, confidence=float(probabilities[best]), layer=2)
