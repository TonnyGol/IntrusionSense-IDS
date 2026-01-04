# src/sniffer_service.py
from scapy.all import sniff, IP, TCP, UDP
import time
from collections import defaultdict
from engine import IDSEngine

class SnifferService:
    def __init__(self, interface_name, log_callback):
        self.interface_name = interface_name
        self.log_callback = log_callback # פונקציה שתקבל את הטקסט ותציג ב-GUI
        self.running = False
        self.engine = IDSEngine()
        self.current_flows = defaultdict(lambda: {
            'start_time': time.time(),
            'packet_count': 0,
            'total_bytes': 0,
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'ack_count': 0,
            'urg_count': 0,
            'ports_scanned': set() # <--- התוספת: אוסף פורטים ייחודיים
        })

    def stop(self):
        self.running = False

    def start(self):
        self.running = True
        self.log_callback(f"📡 Sniffer started on: {self.interface_name}\n")
        
        # פונקציית העצירה של Scapy
        stop_filter = lambda x: not self.running

        try:
            sniff(iface=self.interface_name, prn=self.packet_handler, stop_filter=stop_filter, store=0)
        except Exception as e:
            self.log_callback(f"❌ Error: {str(e)}\n")
        
        self.log_callback("🛑 Sniffer stopped.\n")

    def packet_handler(self, packet):
        if not self.running: return

        try:
            # 1. סינון UDP
            if packet.haslayer(UDP): return
            if not packet.haslayer(IP): return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)
            
            # חילוץ דגלים
            flags = {'S': 0, 'F': 0, 'R': 0, 'P': 0, 'A': 0, 'U': 0}
            dst_port = 0
            if packet.haslayer(TCP):
                dst_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags
                if 'S' in tcp_flags: flags['S'] = 1
                if 'R' in tcp_flags: flags['R'] = 1
                if 'P' in tcp_flags: flags['P'] = 1
                if 'A' in tcp_flags: flags['A'] = 1

            # עדכון סטטיסטיקה
            flow = self.current_flows[flow_key]
            flow['packet_count'] += 1
            flow['total_bytes'] += len(packet)
            flow['syn_count'] += flags['S']
            flow['rst_count'] += flags['R']
            flow['psh_count'] += flags['P']
            flow['ack_count'] += flags['A']

            if dst_port > 0:
                flow['ports_scanned'].add(dst_port)

            duration = time.time() - flow['start_time']
            if duration == 0: duration = 0.0001

            # בדיקה מול המודל
            if flow['packet_count'] % 10 == 0 or flags['S'] == 1:
                features = {
                    'Destination Port': dst_port,
                    'Flow Duration': duration * 1_000_000,
                    'Total Fwd Packets': flow['packet_count'],
                    'Flow Bytes/s': flow['total_bytes'] / duration,
                    'Flow Packets/s': flow['packet_count'] / duration,
                    'SYN Flag Count': flow['syn_count'],
                    'RST Flag Count': flow['rst_count'],
                    'PSH Flag Count': flow['psh_count'],
                    'ACK Flag Count': flow['ack_count']
                }

                result = self.engine.process_and_predict(features)

                if result['is_threat']:
                    label = result['label']

                    if len(flow['ports_scanned']) >= 2:
                        label = "PortScan"

                    msg = f"🚨 ALERT! [{src_ip}] -> [{dst_ip}] : {label} ({result['confidence']:.0%})\n"
                    self.log_callback(msg)
                    
                    # איפוס השיחה
                    del self.current_flows[flow_key]

        except Exception:
            pass