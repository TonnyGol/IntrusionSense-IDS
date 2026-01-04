from engine import IDSEngine

print("--- LIGHTWEIGHT MODEL SANITY CHECK ---")
engine = IDSEngine()

# הגדרת משתנים לסימולציה של התקפה חזקה
packet_count = 2000     # כמות חבילות
duration = 0.5          # משך זמן (חצי שנייה)
avg_packet_size = 60    # גודל חבילה ממוצע (בייטים)

# בניית המילון המדויק לפי 9 הפיצ'רים של המודל החדש
simulation_data = {
    # 1. הקשר (Context)
    'Destination Port': 80,       # תקיפת שרת Web

    # 2. זמן ונפח (Volume & Time)
    'Flow Duration': duration * 1_000_000,       # המרה למיקרו-שניות
    'Total Fwd Packets': packet_count,           # הצפה של חבילות
    'Flow Bytes/s': (packet_count * avg_packet_size) / duration,
    'Flow Packets/s': packet_count / duration,   # קצב חבילות לשנייה (גבוה מאוד!)

    # 3. דגלים (Flags) - האינדיקטורים הכי חזקים להתנהגות
    'SYN Flag Count': packet_count, # בהתקפת DoS הרוב זה SYN
    'RST Flag Count': 0,
    'PSH Flag Count': 0,
    'ACK Flag Count': 0
}

print(f"\nFeeding {len(simulation_data)} features to the Lightweight Engine...")
print("-" * 30)
# הדפסה יפה של הנתונים שנשלחים
for key, val in simulation_data.items():
    print(f"{key}: {val}")
print("-" * 30)

# שליחה למודל
result = engine.process_and_predict(simulation_data)

print(f"\nPrediction: {result['label']}")
print(f"Confidence: {result['confidence']:.2%}")
print(f"Is Threat? {result['is_threat']}")

if result['is_threat']:
    print("\n✅ SUCCESS: The Lightweight Model detected the simulated DoS!")
else:
    print("\n❌ FAILURE: The model missed it.")