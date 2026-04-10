# src/test_web_attack.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
from scapy.all import send, IP, TCP, Raw
from net_utils import get_active_interface_name

TARGET_IP = "8.8.8.8"
IFACE_NAME = get_active_interface_name()
TARGET_PORT = 80 # פורט של Web

print(f"STARTING WEB ATTACK (Category 4)...")
print(f"Interface: {IFACE_NAME}")
print(f"Sending Malicious HTTP Requests to Port {TARGET_PORT}...")

# דימוי של הזרקת SQL בתוך בקשת HTTP
# שים לב: המודל שלנו לא קורא את הטקסט, אבל אורך החבילה והדגלים משפיעים
malicious_payload = "GET /login.php?user=' OR '1'='1' HTTP/1.1\r\nHost: target.com\r\n\r\n"

try:
    while True:
        # שליחה עם דגל PSH (Push) - אופייני לבקשות HTTP
        pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="PA") / Raw(load=malicious_payload)
        send(pkt, iface=IFACE_NAME, verbose=0)
        
        print(f"Sent SQL Injection Packet -> Port {TARGET_PORT}")
        
        # התקפות Web הן בדרך כלל "מטחים" קצרים או קצב מתון
        time.sleep(0.3) 

except KeyboardInterrupt:
    print("\nStopped.")