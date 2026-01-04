# src/test_portscan.py
import time
from scapy.all import send, IP, TCP

TARGET_IP = "10.100.102.1"
# נא לשנות לשם הכרטיס שלך
IFACE_NAME = "Realtek Gaming 2.5GbE Family Controller"

print(f"🚀 STARTING PORT SCAN (Category 2)...")
print(f"Scanning ports on {TARGET_IP}...")

try:
    port = 20
    while True:
        # שליחת חבילת SYN לפורט הנוכחי
        # סריקת פורטים מתאפיינת בשינוי מתמיד של פורט היעד
        pkt = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
        send(pkt, iface=IFACE_NAME, verbose=0)
        
        if port % 10 == 0:
            print(f"Scanning Port: {port}")
        
        # מעבר לפורט הבא (בין 20 ל-1000)
        port += 1
        if port > 1000:
            port = 20 # איפוס
            
        # סריקה היא מהירה, אבל לא הצפה כמו DoS
        time.sleep(0.02)

except KeyboardInterrupt:
    print("\nStopped.")