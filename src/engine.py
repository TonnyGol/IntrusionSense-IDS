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
        # חישוב נתיבים דינמי לטעינת המודל
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, 'models', 'multiClass_ids_model_rf.pkl')
        features_path = os.path.join(base_dir, 'models', 'model_features.pkl')

        print(f"Loading model from: {model_path}")
        
        try:
            self.model = joblib.load(model_path)
            self.expected_features = joblib.load(features_path)
            print(f"[OK] Model loaded. Expecting {len(self.expected_features)} features.")
        except FileNotFoundError:
            print("[ERROR] Model files not found in 'src/models/'.")
            raise

        # Pre-compute: NumPy template (zero-filled) and feature-name-to-index map
        # This avoids building a DataFrame from scratch on every prediction
        self._template = np.zeros(len(self.expected_features), dtype=np.float64)
        self._feature_index = {name: i for i, name in enumerate(self.expected_features)}

    def process_and_predict(self, incoming_data_row):
        """
        מקבל שורה של מידע (Dict),
        מסדר אותה לפי הפיצ'רים שהמודל דורש, ומחזיר תחזית.
        
        Optimized: uses pre-allocated NumPy array instead of DataFrame.
        """
        # 1. Build feature vector from pre-allocated template
        row = self._template.copy()

        for key, value in incoming_data_row.items():
            idx = self._feature_index.get(key)
            if idx is not None:
                row[idx] = value if value == value else 0  # NaN check: NaN != NaN

        # 2. Reshape for model (expects 2D array)
        row_2d = row.reshape(1, -1)

        # 3. Single model call — predict_proba gives us both the class and confidence
        try:
            proba = self.model.predict_proba(row_2d)[0]
            pred_index = int(np.argmax(proba))
            confidence = float(proba[pred_index])
            
            return {
                'label': ATTACK_LABELS.get(pred_index, "Unknown"),
                'is_threat': pred_index != 0,
                'confidence': confidence
            }
        except Exception as e:
            return {
                'label': "Error",
                'is_threat': False,
                'confidence': 0.0,
                'error': str(e)
            }