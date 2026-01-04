import time
import random
from scapy.all import send, IP, TCP, conf

# 1. הגדרת יעד חיצוני (כדי להכריח מעבר דרך הכרטיס הפיזי)
TARGET_IP = "8.8.8.8" 

# 2. הגדרת הכרטיס שממנו שולחים (אותו שם בדיוק כמו ב-Sniffer!)
IFACE_NAME = "Realtek Gaming 2.5GbE Family Controller"

print(f"🚀 FORCING ATTACK THROUGH: {IFACE_NAME}")
print(f"🎯 TARGET: {TARGET_IP}")

try:
    while True:
        # יצירת חבילה
        pkt = IP(dst=TARGET_IP) / TCP(dport=80, flags="S")
        
        # שליחה מפורשת דרך הממשק שלנו
        send(pkt, iface=IFACE_NAME, verbose=0)
        
        print(f"Sent packet to {TARGET_IP} via {IFACE_NAME}")
        time.sleep(0.1) # קצב של 10 בשנייה לבדיקה

except KeyboardInterrupt:
    print("Stopped.")
except Exception as e:
    print(f"Error: {e}")