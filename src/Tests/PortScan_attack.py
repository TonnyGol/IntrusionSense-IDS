# src/test_portscan.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
from scapy.all import send, IP, TCP
from net_utils import get_active_interface_name, get_default_gateway

TARGET_IP = get_default_gateway()
IFACE_NAME = get_active_interface_name()

print(f"STARTING PORT SCAN (Category 2)...")
print(f"Interface: {IFACE_NAME}")
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