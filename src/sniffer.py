from scapy.all import sniff, IP, TCP, UDP, Ether
import pandas as pd
import time
from collections import defaultdict
from engine import IDSEngine # המנוע שבנינו קודם

# --- הגדרות ---
# השם שמצאתם (בדיוק כמו שהעתקתם)
INTERFACE_NAME = "Realtek Gaming 2.5GbE Family Controller" 

# המנוע שלנו
engine = IDSEngine()

# זיכרון זמני לשיחות (Flows)
# מפתח: (Source IP, Dest IP, Src Port, Dst Port, Protocol)
# ערך: נתונים סטטיסטיים
current_flows = defaultdict(lambda: {
    'start_time': time.time(),
    'packet_count': 0,
    'total_bytes': 0,
    'syn_count': 0,
    'fin_count': 0,
    'urg_count': 0,
    'ack_count': 0,
    'psh_count': 0,
    'rst_count': 0
})

print(f"\n📡 STARTING SNIFFER ON: {INTERFACE_NAME}")
print("Press Ctrl+C to stop...")

def extract_features(packet):
    """
    הפונקציה הזו נקראת עבור *כל* חבילה שעוברת ברשת.
    היא מעדכנת את הסטטיסטיקה ושולחת למודל לבדיקה.
    """
    try:
        # אנחנו מתעניינים רק בחבילות IP (לא רעש רקע אחר)
        if not packet.haslayer(IP):
            return

        # 1. זיהוי השיחה (Flow Key)
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        src_port = 0
        dst_port = 0
        
        # חילוץ פורטים ודגלים (אם זה TCP/UDP)
        flags = {'S': 0, 'F': 0, 'U': 0, 'A': 0, 'P': 0, 'R': 0}
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # בדיקת דגלים
            tcp_flags = packet[TCP].flags
            if 'S' in tcp_flags: flags['S'] = 1
            if 'F' in tcp_flags: flags['F'] = 1
            if 'U' in tcp_flags: flags['U'] = 1
            if 'A' in tcp_flags: flags['A'] = 1
            if 'P' in tcp_flags: flags['P'] = 1
            if 'R' in tcp_flags: flags['R'] = 1
            
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # מפתח ייחודי לשיחה הזו
        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
        
        # 2. עדכון הסטטיסטיקה בזמן אמת
        flow = current_flows[flow_key]
        flow['packet_count'] += 1
        flow['total_bytes'] += len(packet)
        flow['syn_count'] += flags['S']
        flow['fin_count'] += flags['F']
        flow['urg_count'] += flags['U']
        flow['ack_count'] += flags['A']
        flow['psh_count'] += flags['P']
        flow['rst_count'] += flags['R']
        
        # חישוב משך זמן השיחה
        duration = time.time() - flow['start_time']
        # המרה למיקרו-שניות (כמו שהמודל רגיל)
        duration_micro = duration * 1000000 

        # 3. הכנת הנתונים למודל (Feature Mapping)
        # אנחנו ממפים את מה שאספנו לשמות שהמודל מכיר
        features = {
            'Flow Duration': duration_micro,
            'Total Fwd Packets': flow['packet_count'], # הנחה פשוטה: הכל נחשב קדימה כרגע
            'Total Length of Fwd Packets': flow['total_bytes'],
            'Flow Bytes/s': (flow['total_bytes'] / duration) if duration > 0 else 0,
            'Flow Packets/s': (flow['packet_count'] / duration) if duration > 0 else 0,
            'SYN Flag Count': flow['syn_count'],
            'FIN Flag Count': flow['fin_count'],
            'RST Flag Count': flow['rst_count'],
            'PSH Flag Count': flow['psh_count'],
            'ACK Flag Count': flow['ack_count'],
            'URG Flag Count': flow['urg_count'],
            'Destination Port': dst_port # למרות שהסרנו את זה באימון, לפעמים המנוע מצפה לראות את העמודה (אפילו אם היא לא משפיעה)
        }
        
        # 4. שליחה למנוע (רק כל חבילה עשירית כדי לא להעמיס, או אם יש חשד)
        # (כרגע נשלח כל חבילה כדי לראות את זה עובד יפה במסך)
        result = engine.process_and_predict(features)
        
        # 5. הדפסה
        if result['is_threat']:
            print(f"🚨 ALERT! [{src_ip} -> {dst_ip}] : {result['label']} ({result['confidence']:.0%})")
        else:
            # מדפיסים נקודה ירוקה כדי לדעת שזה חי
            print(".", end="", flush=True)

    except Exception as e:
        # לפעמים יש חבילות מוזרות שגורמות לשגיאה, נתעלם מהן
        pass

# --- הפעלת ההאזנה ---
# store=0 אומר לא לשמור בזיכרון (כדי לא לפוצץ את ה-RAM)
try:
    sniff(iface=INTERFACE_NAME, prn=extract_features, store=0)
except OSError:
    print(f"\n❌ Error: Could not find interface '{INTERFACE_NAME}'.")
    print("Try running VS Code as ADMINISTRATOR.")
    print("Or try using the index number in find_adapter.py instead of the name.")