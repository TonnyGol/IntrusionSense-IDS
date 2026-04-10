# src/test_patator.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
from scapy.all import send, IP, TCP, Raw
from net_utils import get_active_interface_name

TARGET_IP = "8.8.8.8"
IFACE_NAME = get_active_interface_name()
TARGET_PORT = 21 # פורט של FTP (הקלאסי להתקפות Patator)

print(f"STARTING PATATOR / BRUTE FORCE (Category 3)...")
print(f"Interface: {IFACE_NAME}")
print(f"Simulating FTP login attempts on Port {TARGET_PORT}...")

# דימוי של פקודת התחברות לשרת FTP
fake_payload = "USER admin\r\nPASS 123456\r\n"

try:
    while True:
        # התקפות Brute Force משתמשות בחיבור קיים, ולכן נראה דגלי PSH ו-ACK
        pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="PA") / Raw(load=fake_payload)
        send(pkt, iface=IFACE_NAME, verbose=0)
        
        print(f"Sent FTP Login Attempt -> Port {TARGET_PORT}")
        
        # קצב של ניחושים (קצת יותר איטי מ-DoS)
        time.sleep(0.1)

except KeyboardInterrupt:
    print("\nStopped.")