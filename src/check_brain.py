import joblib
import pandas as pd
import os

# טעינת המודל
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'models', 'multiClass_ids_model_rf.pkl')
features_path = os.path.join(base_dir, 'models', 'model_features.pkl')

print(f"Loading model from {model_path}...")
model = joblib.load(model_path)
feature_names = joblib.load(features_path)

# בדיקת חשיבות פיצ'רים (רק אם זה Random Forest)
if hasattr(model, 'feature_importances_'):
    print("\n🔍 TOP MOST IMPORTANT FEATURES:")
    print("-" * 40)
    
    # יצירת טבלה של שם מול חשיבות
    importances = model.feature_importances_
    feature_imp = pd.DataFrame(sorted(zip(importances, feature_names)), columns=['Value','Feature'])
    
    # הדפסת ה-15 הכי חשובים (מהגדול לקטן)
    top_15 = feature_imp.sort_values(by="Value", ascending=False).head(15)
    print(top_15)
    
    print("-" * 40)
    print("These are the columns that MUST not be 0 in your simulation!")
else:
    print("Model does not support feature importance (not a Tree/Forest model).")