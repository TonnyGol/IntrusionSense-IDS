# src/engine.py
import os
import warnings
import joblib
import numpy as np
from config import ATTACK_LABELS

# Suppress sklearn warning about feature names — we use NumPy arrays
# for performance but maintain correct feature order via _feature_index
warnings.filterwarnings("ignore", message="X does not have valid feature names")

class IDSEngine:
    def __init__(self):
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

        self._template_l1 = np.zeros(len(self.l1_expected_features), dtype=np.float64)
        self._feature_index_l1 = {name: i for i, name in enumerate(self.l1_expected_features)}
        
        # --- 2. Load Layer 2 (Deep Analysis) ---
        model_file = 'layer2_model.pkl'
        feat_file = 'layer2_features.pkl'

        model_path = os.path.join(base_dir, 'models', model_file)
        features_path = os.path.join(base_dir, 'models', feat_file)

        print(f"Loading Layer 2 model from: {model_path}")
        try:
            self.model = joblib.load(model_path)
            self.expected_features = joblib.load(features_path)
            print(f"[OK] Layer 2 loaded. Expecting {len(self.expected_features)} features.")
        except FileNotFoundError:
            print("[ERROR] Layer 2 files not found in 'src/models/'.")
            raise

        self._template_l2 = np.zeros(len(self.expected_features), dtype=np.float64)
        self._feature_index_l2 = {name: i for i, name in enumerate(self.expected_features)}

    def process_and_predict(self, incoming_data_row):
        """
        Runs the 2-Stage Pipeline:
        1. Layer 1 checks if it's Normal or Suspicious.
        2. If Suspicious, Layer 2 identifies the specific attack.
        """
        # ==========================================
        # STAGE 1: GATEKEEPER
        # ==========================================
        row_l1 = self._template_l1.copy()
        for key, value in incoming_data_row.items():
            idx = self._feature_index_l1.get(key)
            if idx is not None:
                row_l1[idx] = value if value == value else 0
                
        row_2d_l1 = row_l1.reshape(1, -1)

        try:
            l1_pred = int(self.l1_model.predict(row_2d_l1)[0])
            if l1_pred == 0:
                # Normal Traffic -> Stop here and return
                return {
                    'label': 'Normal Traffic',
                    'is_threat': False,
                    'confidence': 1.0,
                    'layer': 1
                }
            else:
                print("[IDS ENGINE] Layer 1 caught suspicious traffic! Handing off to Layer 2...")
        except Exception as e:
            return {'label': "Error L1", 'is_threat': False, 'confidence': 0.0, 'error': str(e)}

        # ==========================================
        # STAGE 2: DEEP ANALYSIS
        # ==========================================
        row_l2 = self._template_l2.copy()
        for key, value in incoming_data_row.items():
            idx = self._feature_index_l2.get(key)
            if idx is not None:
                row_l2[idx] = value if value == value else 0
                
        row_2d_l2 = row_l2.reshape(1, -1)

        try:
            proba = self.model.predict_proba(row_2d_l2)[0]
            pred_index = int(np.argmax(proba))
            confidence = float(proba[pred_index])
            
            label_str = ATTACK_LABELS.get(pred_index, "Unknown")
            is_threat = "Normal" not in label_str and "BENIGN" not in label_str
            
            return {
                'label': label_str,
                'is_threat': is_threat,
                'confidence': confidence,
                'layer': 2
            }
        except Exception as e:
            return {'label': "Error L2", 'is_threat': False, 'confidence': 0.0, 'error': str(e)}