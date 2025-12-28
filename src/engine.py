# src/engine.py
import os
import joblib
import pandas as pd
import numpy as np
from config import ATTACK_LABELS

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
            print(f"✅ Model loaded. Expecting {len(self.expected_features)} features.")
        except FileNotFoundError:
            print("❌ Error: Model files not found in 'src/models/'.")
            raise

    def process_and_predict(self, incoming_data_row):
        """
        מקבל שורה של מידע (Dict או Series),
        מסדר אותה לפי הפיצ'רים שהמודל דורש, ומחזיר תחזית.
        """
        # 1. המרה ל-DataFrame
        if isinstance(incoming_data_row, dict):
             df_input = pd.DataFrame([incoming_data_row])
        else:
             df_input = pd.DataFrame([incoming_data_row])

        # ניקוי רווחים בשמות העמודות שהתקבלו (תמיד טוב)
        df_input.columns = df_input.columns.str.strip()

        # 2. בניית וקטור הפיצ'רים הסופי
        final_df = pd.DataFrame()

        for feature in self.expected_features:
            # בדיקה פשוטה: האם הפיצ'ר קיים במידע שהתקבל?
            if feature in df_input.columns:
                final_df[feature] = df_input[feature]
            else:
                # אם חסר מידע, נמלא באפס (Fail Safe)
                final_df[feature] = 0
        
        # 3. וידוא שאין NaN
        final_df.fillna(0, inplace=True)

        # 4. ביצוע התחזית
        try:
            pred_index = self.model.predict(final_df)[0]
            confidence = np.max(self.model.predict_proba(final_df)[0])
            
            return {
                'label': ATTACK_LABELS.get(pred_index, "Unknown"),
                'is_threat': pred_index != 0, # אמת אם זה לא 0
                'confidence': confidence
            }
        except Exception as e:
            return {
                'label': "Error",
                'is_threat': False,
                'confidence': 0.0,
                'error': str(e)
            }