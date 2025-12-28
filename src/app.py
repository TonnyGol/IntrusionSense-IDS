# src/app.py
import pandas as pd
import time
import random
from engine import IDSEngine

def run_simulation():
    # 1. אתחול המנוע
    try:
        engine = IDSEngine()
    except Exception as e:
        print(f"Critical Error: {e}")
        return

    print("\n🚀 STARTING IDS ENGINE CHECK 🚀")
    print("(Running in simulation mode with dummy data)")
    print("-" * 50)
    time.sleep(1)

    # 2. יצירת נתונים פיקטיביים לבדיקה טכנית
    # (בשלב הבא נחליף את זה בקריאה מכרטיס הרשת או מקובץ CSV שלך)
    
    # נמציא 5 שורות של נתונים
    dummy_rows = []
    for _ in range(5):
        row = {
            'Flow Duration': random.randint(100, 100000),
            'Total Fwd Packets': random.randint(1, 50),
            'Flow Bytes/s': random.uniform(0, 5000),
            # אפשר להוסיף עוד פיצ'רים כאן...
            # שים לב: המנוע ישלים ב-0 כל מה שלא נכתוב כאן
        }
        dummy_rows.append(row)

    # 3. הרצת הלולאה
    for i, row in enumerate(dummy_rows):
        
        # --- שליחה למנוע ---
        result = engine.process_and_predict(row)
        
        # --- הדפסה ---
        status = "⚠️ ALERT" if result['is_threat'] else "✅ SAFE"
        print(f"Packet #{i+1} | {status} | Prediction: {result['label']} (Conf: {result['confidence']:.2%})")
        
        time.sleep(0.5)

    print("-" * 50)
    print("Engine is running correctly.")

if __name__ == "__main__":
    run_simulation()