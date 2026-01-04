import pandas as pd
import os
from engine import IDSEngine

# הגדרות
CSV_PATH = '../data/raw/02-15-2018.csv'  # נתיב יחסי, ודא שהוא נכון
engine = IDSEngine()

print("\n--- REAL DATA SANITY CHECK ---")
print(f"Loading 100 rows from {CSV_PATH}...")

try:
    # טעינת דוגמית וניקוי רווחים
    df = pd.read_csv(CSV_PATH, nrows=100)
    df.columns = df.columns.str.strip()
    
    # נחפש שורה שהיא בטוח DoS (בקובץ הזה הרוב DoS)
    # נבחר שורה אקראית, נניח שורה 50
    real_attack_row = df.iloc[50].to_dict()
    
    # הדפסה של הלייבל המקורי בקובץ (רק לוודא)
    print(f"Original Label in CSV: {real_attack_row.get('Label', 'Unknown')}")
    
    # --- הרצת המנוע ---
    print("Feeding this row to the Engine...")
    
    # המנוע שלנו כבר מכיל בתוכו את המילון (אם הטמעת אותו) 
    # או שהוא ינסה למצוא התאמה. בוא נראה מה קורה.
    result = engine.process_and_predict(real_attack_row)
    
    print("\n--- RESULTS ---")
    print(f"Prediction: {result['label']}")
    print(f"Confidence: {result['confidence']:.4%}")
    print(f"Is Threat?  {result['is_threat']}")
    
    if result['is_threat']:
        print("\n✅ SUCCESS: The engine recognized a REAL attack row!")
    else:
        print("\n❌ FAILURE: Even real data failed. Mapping issue confirmed.")
        # אם זה נכשל, נדפיס אילו עמודות המנוע קיבל כ-0
        print("Debug Hint: Check if column names in CSV match model expectations.")

except FileNotFoundError:
    print("Error: Could not find the CSV file. Check path.")