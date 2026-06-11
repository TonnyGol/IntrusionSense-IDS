from scapy.all import sniff, IP, TCP, UDP
import time
from collections import defaultdict
from engine import IDSEngine
from config import INTERFACE_NAME

# --- הגדרות ---
engine = IDSEngine()

# שינוי קריטי: קיבוץ לפי IP בלבד (Src -> Dst)
# זה יאפשר לנו לתפוס התקפות גם אם הפורט משתנה כל רגע
current_flows = defaultdict(lambda: {
    'start_time': time.time(),
    'packet_count': 0,
    'total_bytes': 0,
    'syn_count': 0,
    'fin_count': 0,
    'rst_count': 0,
    'psh_count': 0,
    'ack_count': 0,
    'urg_count': 0,
    'fwd_packet_length_max': 0,
    'fwd_packet_length_min': 999999
})

print(f"\n📡 SNIFFER V2 (Aggressive Aggregation) ON: {INTERFACE_NAME}")
print("Ignoring UDP traffic (Discord/Zoom filter active)...")

def extract_features(packet):
    try:
        # 1. סינון UDP (דיסקורד, זום, משחקים)
        # זה ינקה לכם את הרעש מהמסך
        if packet.haslayer(UDP):
            return

        # סינון חבילות שאינן IP
        if not packet.haslayer(IP):
            return

        # חילוץ כתובות
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # 2. שינוי מפתח ה-Flow: מתעלמים מהפורט!
        # ככה נצבור את כל החבילות מהתוקף למקום אחד
        flow_key = (src_ip, dst_ip) 
        
        # חילוץ מידע מ-TCP
        flags = {'S': 0, 'F': 0, 'R': 0, 'P': 0, 'A': 0, 'U': 0}
        dst_port = 0
        
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            # המרה זריזה של דגלים למספרים
            if 'S' in tcp_flags: flags['S'] = 1
            if 'F' in tcp_flags: flags['F'] = 1
            if 'R' in tcp_flags: flags['R'] = 1
            if 'P' in tcp_flags: flags['P'] = 1
            if 'A' in tcp_flags: flags['A'] = 1
            if 'U' in tcp_flags: flags['U'] = 1

        # 3. עדכון הסטטיסטיקה (מצטבר!)
        flow = current_flows[flow_key]
        flow['packet_count'] += 1
        pkt_len = len(packet)
        flow['total_bytes'] += pkt_len
        
        if pkt_len > flow['fwd_packet_length_max']:
            flow['fwd_packet_length_max'] = pkt_len
        if pkt_len < flow['fwd_packet_length_min']:
            flow['fwd_packet_length_min'] = pkt_len
        
        # עדכון דגלים
        flow['syn_count'] += flags['S']
        flow['fin_count'] += flags['F']
        flow['rst_count'] += flags['R']
        flow['psh_count'] += flags['P']
        flow['ack_count'] += flags['A']
        flow['urg_count'] += flags['U']

        # חישוב זמנים
        duration = time.time() - flow['start_time']
        duration_micro = duration * 1_000_000
        
        # מניעת חלוקה באפס
        if duration == 0: duration = 0.00001

        # 4. הכנת הפיצ'רים למודל
        # שימו לב: המספרים פה יגדלו מהר מאוד כשהתוקף יעבוד
        features = {
            'Flow Duration': duration_micro,
            'Total Fwd Packets': flow['packet_count'], 
            'Total Length of Fwd Packets': flow['total_bytes'],
            'Fwd Packet Length Max': flow['fwd_packet_length_max'],
            'Fwd Packet Length Min': flow['fwd_packet_length_min'] if flow['fwd_packet_length_min'] != 999999 else pkt_len,
            'Fwd Packet Length Mean': flow['total_bytes'] / flow['packet_count'],
            'Flow Bytes/s': flow['total_bytes'] / duration,
            'Flow Packets/s': flow['packet_count'] / duration,
            'SYN Flag Count': flow['syn_count'],
            'FIN Flag Count': flow['fin_count'],
            'RST Flag Count': flow['rst_count'],
            'PSH Flag Count': flow['psh_count'],
            'ACK Flag Count': flow['ack_count'],
            'URG Flag Count': flow['urg_count']
        }
        
        # 5. בדיקה מול המודל
        # נשלח לבדיקה רק אם הצטבר מספיק מידע (כל חבילה עשירית) או אם זה חשוד (SYN)
        # זה עוזר למודל לקבל "תמונה מלאה" ולא חבילה בודדת
        if flow['packet_count'] % 10 == 0 or flags['S'] == 1:
            result = engine.process_and_predict(features)
            
            if result['is_threat']:
                # הדפסה אדומה בוהקת
                print(f"🚨 ALERT! [{src_ip}] -> [{dst_ip}] : {result['label']} "
                      f"(Pkts: {flow['packet_count']}, Conf: {result['confidence']:.0%})")
                del current_flows[flow_key]
            else:
                # נקודה ירוקה - הכל טוב
                print(".", end="", flush=True)

    except Exception:
        pass

# הפעלה
try:
    sniff(iface=INTERFACE_NAME, prn=extract_features, store=0)
except KeyboardInterrupt:
    print("\nStopped.")