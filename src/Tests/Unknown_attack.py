# src/test_anomaly.py
import time
import random
from scapy.all import send, IP, TCP, Raw

TARGET_IP = "8.8.8.8"
IFACE_NAME = "Realtek Gaming 2.5GbE Family Controller"

print(f"🚀 STARTING ANOMALY TEST (Category 5?)...")

try:
    while True:
        # שליחת חבילה "שבורה" או מוזרה לפורט גבוה
        # דגלים מוזרים (למשל FIN + URG + PSH ביחד - נקרא Xmas scan)
        flags = "FPU" 
        payload = random.randbytes(100) # סתם זבל בינארי
        
        pkt = IP(dst=TARGET_IP) / TCP(dport=443, flags=flags) / Raw(load=payload)
        send(pkt, iface=IFACE_NAME, verbose=0)
        
        print(f"Sent Malformed Packet (Flags: {flags})")
        time.sleep(0.2)

except KeyboardInterrupt:
    print("\nStopped.")