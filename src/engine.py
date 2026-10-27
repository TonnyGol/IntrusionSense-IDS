import logging
import os
import warnings
import joblib
import numpy as np
from config import ATTACK_LABELS, settings

warnings.filterwarnings("ignore", message="X does not have valid feature names")

log = logging.getLogger(__name__)


class IDSEngine:
    def __init__(self):
        self.l1_threshold = settings.l1_threshold
        base_dir = os.path.dirname(os.path.abspath(__file__))

        # --- 1. Load Layer 1 (Gatekeeper) ---
        l1_model_path = os.path.join(base_dir, 'models', 'layer1_model.pkl')
        l1_features_path = os.path.join(base_dir, 'models', 'layer1_features.pkl')

        print(f"Loading Layer 1 model from: {l1_model_path}")
        try:
            self.l1_model = joblib.load(l1_model_path)
            self.l1_expected_features = joblib.load(l1_features_path)
            print(f"[OK] Layer 1 loaded. Expecting {len(self.l1_expected_features)} features.")
        except FileNotFoundError:
            print("[ERROR] Layer 1 files not found. Please ensure Layer1_training.ipynb was run.")
            raise

        # --- 2. Load Layer 2 (Deep Analysis) ---
        l2_model_path = os.path.join(base_dir, 'models', 'layer2_model.pkl')
        l2_features_path = os.path.join(base_dir, 'models', 'layer2_features.pkl')

        print(f"Loading Layer 2 model from: {l2_model_path}")
        try:
            self.l2_model = joblib.load(l2_model_path)
            self.l2_expected_features = joblib.load(l2_features_path)
            print(f"[OK] Layer 2 loaded. Expecting {len(self.l2_expected_features)} features.")
        except FileNotFoundError:
            print("[ERROR] Layer 2 files not found in 'src/models/'.")
            raise

    @staticmethod
    def _vectorize(features, expected):
        """Feature dict -> 1-row array in model order. A missing or non-finite value is a bug, not a 0."""
        missing = [name for name in expected if name not in features]
        if missing:
            raise ValueError(f"missing features: {missing}")
        row = np.array([features[name] for name in expected], dtype=np.float64)
        if not np.isfinite(row).all():
            bad = [name for name, v in zip(expected, row) if not np.isfinite(v)]
            raise ValueError(f"non-finite features: {bad}")
        return row.reshape(1, -1)

    @staticmethod
    def _engine_error(layer, exc):
        # fail closed: a flow the engine could not judge is reported, never silently marked safe
        log.error("Layer %d inference failed: %s", layer, exc)
        return {'label': 'Engine Error', 'is_threat': True, 'confidence': None, 'layer': layer, 'error': str(exc)}

    def process_and_predict(self, incoming_data_row):
        """
        Runs the 2-Stage Pipeline:
        1. Layer 1 checks if it's Normal or Suspicious.
        2. If Suspicious, Layer 2 identifies the specific attack.
        """
        # ==========================================
        # STAGE 1: GATEKEEPER
        # ==========================================
        try:
            row_2d_l1 = self._vectorize(incoming_data_row, self.l1_expected_features)
            # Predict probability instead of a hard class (0 or 1)
            # This allows us to lower the threshold for "Suspicious"
            if hasattr(self.l1_model, "predict_proba"):
                proba = self.l1_model.predict_proba(row_2d_l1)[0]
                # Index 1 corresponds to class 1 (Suspicious)
                # If probability of Suspicious > threshold, pass to Layer 2
                if len(proba) > 1 and proba[1] > self.l1_threshold:
                    l1_pred = 1
                else:
                    l1_pred = 0
            else:
                l1_pred = int(self.l1_model.predict(row_2d_l1)[0])

            if l1_pred == 0:
                # Normal Traffic -> Stop here and return
                return {
                    'label': 'Normal Traffic',
                    'is_threat': False,
                    'confidence': float(1 - proba[1]) if hasattr(self.l1_model, "predict_proba") else None,
                    'layer': 1
                }
            else:
                log.debug("Layer 1 flagged the flow as suspicious, handing off to Layer 2")
        except Exception as e:
            return self._engine_error(1, e)

        # ==========================================
        # STAGE 2: DEEP ANALYSIS
        # ==========================================
        try:
            row_2d_l2 = self._vectorize(incoming_data_row, self.l2_expected_features)
            proba = self.l2_model.predict_proba(row_2d_l2)[0]
            pred_index = int(np.argmax(proba))
            confidence = float(proba[pred_index])

            # Layer 2 only sees suspicious flows and every class it knows is an attack
            pred_class = self.l2_model.classes_[pred_index]
            # classes_ holds either the integer ids in ATTACK_LABELS or the label strings themselves
            label_str = ATTACK_LABELS.get(pred_class) if isinstance(pred_class, (int, np.integer)) else str(pred_class)
            if label_str is None:
                raise ValueError(f"unknown Layer 2 class id: {pred_class}")

            return {
                'label': label_str,
                'is_threat': True,
                'confidence': confidence,
                'layer': 2
            }
        except Exception as e:
            return self._engine_error(2, e)
