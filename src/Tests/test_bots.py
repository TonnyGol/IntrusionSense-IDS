import sys
import os
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine import IDSEngine

def run_verification():
    print("[*] Loading CSV training dataset...")
    csv_path = '../../data/processed/cicids2017_cleaned.csv'
    
    if not os.path.exists(csv_path):
        print(f"[ERROR] Could not find {csv_path}")
        return

    df = pd.read_csv(csv_path)
    
    attack_name = "Bots"
    attack_df = df[df['Attack Type'] == attack_name]
    
    if len(attack_df) == 0:
        print(f"[ERROR] No '{attack_name}' attacks found in the CSV!")
        return

    num_tests = min(50, len(attack_df))
    print(f"\n[*] Testing the first {num_tests} '{attack_name}' attacks...")
    
    engine = IDSEngine()
    
    success_count = 0
    caught_count = 0
    missed_count = 0
    
    for i in range(num_tests):
        real_attack_row = attack_df.iloc[i].to_dict()
        real_attack_row.pop('Attack Type', None)
        real_attack_row.pop('Is_Suspicious', None)

        result = engine.process_and_predict(real_attack_row)
        is_threat = result.get('is_threat')
        label = result.get('label')
        
        if is_threat and label == attack_name:
            status = "✅ PERFECT MATCH"
            success_count += 1
            caught_count += 1
        elif is_threat:
            status = f"⚠️ CAUGHT AS {label}"
            caught_count += 1
        else:
            status = "❌ MISSED (Normal Traffic)"
            missed_count += 1
            
        print(f"Test {i+1:02d} -> {status}")

    print(f"\n[*] Summary for {attack_name}:")
    print(f"    - Total Tested: {num_tests}")
    print(f"    - Successfully Caught (Any Alert): {caught_count}")
    print(f"    - Perfect Match ({attack_name}): {success_count}")
    print(f"    - Missed: {missed_count}")

if __name__ == '__main__':
    run_verification()
