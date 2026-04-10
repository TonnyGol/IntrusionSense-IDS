import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
import random
from scapy.all import send, IP, TCP
from net_utils import get_active_interface_name

# הגדרת יעד סתמי (לא באמת קיים, רק כדי לייצר תעבורה יוצאת)
TARGET_IP = "172.23.240.1" 
IFACE_NAME = get_active_interface_name()

print(f"STARTING ATTACK SIMULATION ON {TARGET_IP}...")
print(f"Interface: {IFACE_NAME}")
print("Sending fast SYN packets to trigger IDS...")

# נייצר התקפה של 5 שניות
try:
    count = 0
    while True:
        # יצירת חבילה מזויפת
        # מפורט אקראי -> לפורט 80
        # דגל S = SYN (התחלת שיחה, כמו בהתקפת DoS או סריקה)
        packet = IP(dst=TARGET_IP) / TCP(dport=80, sport=random.randint(1024, 65535), flags="S")
        
        # שליחה (verbose=0 כדי לא להציף את המסך בהודעות של Scapy)
        send(packet, iface=IFACE_NAME, verbose=0)
        
        count += 1
        if count % 100 == 0:
            print(f"Sent {count} packets...")
            
        # דיליי קצרצר כדי לא לתקוע את המחשב לגמרי, אבל מספיק מהיר כדי להחשד
        time.sleep(0.01)

except KeyboardInterrupt:
    print("\nAttack stopped.")