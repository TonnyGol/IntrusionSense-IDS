# src/Interface/heuristic_engine.py
import re
import time
from collections import defaultdict
import sys
import os

# Import config
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import config

class HeuristicEngine:
    def __init__(self):
        self.config = getattr(config, 'HEURISTIC_CONFIG', {})
        self.ip_connection_tracker = defaultdict(list)
        self.db_rules = []
                
        # Regex patterns for Deep Packet Inspection
        self.web_attack_patterns = [
            re.compile(r'(?i)UNION\s+SELECT'),
            re.compile(r'(?i)DROP\s+TABLE'),
            re.compile(r'(?i)\'\s*OR\s*\'1\'=\'1'),
            re.compile(r'(?i)<script>'),
            re.compile(r'(?i)onerror='),
            re.compile(r'\.\./'),
            re.compile(r'/etc/passwd')
        ]
        
        # Load custom DB rules on startup
        self.reload_rules()

    def reload_rules(self):
        """Fetch active custom rules from the database and parse them into memory."""
        try:
            from database.connection import SessionLocal
            from database.models import Rule
            
            with SessionLocal() as session:
                active_rules = session.query(Rule).filter_by(IsActive=True).all()
                parsed_rules = []
                for r in active_rules:
                    if not r.ConditionText: continue
                    text = r.ConditionText.strip()
                    field = None
                    value = None
                    
                    if text.startswith("Source IP "):
                        field = "Source IP"
                        value = text[10:].strip()
                    elif text.startswith("Dest IP "):
                        field = "Dest IP"
                        value = text[8:].strip()
                    elif text.startswith("Port "):
                        field = "Port"
                        value = text[5:].strip()
                    elif text.startswith("Protocol "):
                        field = "Protocol"
                        value = text[9:].strip()
                    elif text.startswith("Packet Count "):
                        field = "Packet Count"
                        value = text[13:].strip()
                    else:
                        continue
                        
                    parsed_rules.append({
                        "name": r.RuleName,
                        "field": field,
                        "value": value,
                        "action": r.Severity
                    })
                self.db_rules = parsed_rules
        except Exception as e:
            print(f"Error loading DB rules: {e}")

    def should_drop_packet(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Evaluate if the packet matches a Drop/Block rule."""
        if not self.db_rules: return False
        
        proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
        
        for r in self.db_rules:
            if r['action'] != "Drop / Block":
                continue
                
            match = False
            if r['field'] == "Source IP" and r['value'] == src_ip:
                match = True
            elif r['field'] == "Dest IP" and r['value'] == dst_ip:
                match = True
            elif r['field'] == "Port" and str(r['value']) in (str(src_port), str(dst_port)):
                match = True
            elif r['field'] == "Protocol" and r['value'].upper() == proto_str:
                match = True
                
            if match:
                return True
        return False


    def track_connection(self, src_ip):
        """Track new connections for rate limiting (Brute Force evasion fix)."""
        if not self.config.get("ENABLE_BRUTE_FORCE_RATE_LIMIT", True):
            return
            
        now = time.time()
        time_window = self.config.get("BRUTE_FORCE_TIME_WINDOW", 60)
        
        # Add new connection timestamp
        self.ip_connection_tracker[src_ip].append(now)
        
        # Clean up old timestamps outside the window
        self.ip_connection_tracker[src_ip] = [
            t for t in self.ip_connection_tracker[src_ip] 
            if now - t <= time_window
        ]

    def evaluate_flow(self, flow_key, flow, features):
        """
        Evaluate the flow against hardcoded heuristic rules.
        Returns a threat dictionary if matched, else None.
        """
        src_ip = flow_key[0]
        dst_ip = flow_key[1]
        src_port = flow_key[2]
        dst_port = flow_key[3]
        protocol = flow_key[4]
        now = time.time()
        
        # 0. Custom DB Rules (Alert Actions)
        for r in self.db_rules:
            if r['action'] == "Drop / Block":
                continue # Handled per-packet in should_drop_packet
                
            match = False
            if r['field'] == "Source IP" and r['value'] == src_ip:
                match = True
            elif r['field'] == "Dest IP" and r['value'] == dst_ip:
                match = True
            elif r['field'] == "Port" and str(r['value']) in (str(src_port), str(dst_port)):
                match = True
            elif r['field'] == "Protocol":
                proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
                if r['value'].upper() == proto_str:
                    match = True
            elif r['field'] == "Packet Count":
                total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
                try:
                    if total_packets >= int(r['value']):
                        match = True
                except ValueError:
                    pass
                    
            if match:
                severity_map = {
                    "Alert High": 0.99,
                    "Alert Medium": 0.80,
                    "Alert Low": 0.50
                }
                conf = severity_map.get(r['action'], 0.90)
                return {
                    'is_threat': True,
                    'label': r['name'] or 'Custom Rule',
                    'confidence': conf,
                    'rule_triggered': f"Custom Rule: {r['name']}"
                }

        
        # 1. Web Attack Deep Packet Inspection (DPI)
        if self.config.get("ENABLE_WEB_DPI", True):
            for payload in flow.get('payload_samples', []):
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    for pattern in self.web_attack_patterns:
                        if pattern.search(decoded_payload):
                            return {
                                'is_threat': True,
                                'label': 'Web Attacks',
                                'confidence': 0.99,
                                'rule_triggered': 'DPI Match (Web Attack Signature)'
                            }
                except Exception:
                    continue

        # 2. Stealth SYN Scan Detection
        if self.config.get("ENABLE_SYN_SCAN", True):
            # A SYN scan probe typically has SYN set, no ACK, and very few packets
            total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
            if flow.get('syn_flag', 0) == 1 and flow.get('ack_flag', 0) == 0 and total_packets <= 2:
                return {
                    'is_threat': True,
                    'label': 'Port Scanning',
                    'confidence': 0.95,
                    'rule_triggered': 'Heuristic: Stealth SYN Probe'
                }

        # 3. Brute Force Connection Rate Limiting
        if self.config.get("ENABLE_BRUTE_FORCE_RATE_LIMIT", True):
            max_conns = self.config.get("BRUTE_FORCE_MAX_CONNECTIONS", 20)
            if len(self.ip_connection_tracker.get(src_ip, [])) > max_conns:
                return {
                    'is_threat': True,
                    'label': 'Brute Force',
                    'confidence': 0.90,
                    'rule_triggered': f'Heuristic: High Connection Rate (>{max_conns}/min)'
                }

        # No heuristics matched, fall back to ML model
        return None
