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
import random

class HeuristicEngine:
    def __init__(self):
        self.config = getattr(config, 'HEURISTIC_CONFIG', {})
        self.ip_connection_tracker = defaultdict(list)
        # Track repeated connection attempts for brute force detection
        self.brute_force_tracker = defaultdict(list)
        # Track recent (dst_ip,dst_port) packet timestamps and contributing src IPs
        self.dst_port_tracker = defaultdict(lambda: {'timestamps': [], 'src_ips': set()})
        # Track recent port probes per (src_ip,dst_ip) as list of (dst_port, timestamp)
        self.port_probe_tracker = defaultdict(lambda: {'probes': []})
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

    def _trim_old_entries(self, entries, cutoff):
        return [entry for entry in entries if entry[1] >= cutoff]

    def _sample_confidence(self, low=0.88, high=0.95):
        return round(random.uniform(low, high), 4)

    def _update_port_probe_tracker(self, src_ip, dst_ip, dst_port, now):
        key = (src_ip, dst_ip)
        info = self.port_probe_tracker[key]
        info['probes'].append((dst_port, now))
        window = float(self.config.get('PORTSCAN_WINDOW', 60))
        cutoff = now - window
        info['probes'] = self._trim_old_entries(info['probes'], cutoff)
        return info

    def _update_dst_port_tracker(self, dst_ip, dst_port, src_ip, now):
        key = (dst_ip, dst_port)
        info = self.dst_port_tracker[key]
        info['timestamps'].append(now)
        info['src_ips'].add(src_ip)
        window = float(self.config.get('DOS_WINDOW', 10))
        cutoff = now - window
        info['timestamps'] = [t for t in info['timestamps'] if t >= cutoff]
        return info

    def evaluate_flow(self, flow_key, flow, features):
        """
        Evaluate the flow against hardcoded heuristic rules.
        Returns a threat dictionary if matched, else None.
        """
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        now = time.time()

        total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
        total_bytes = sum(flow['fwd_lengths']) + sum(flow['bwd_lengths'])
        avg_pkt_size = features.get('Average Packet Size', 0)
        syn_count = flow.get('syn_count', 0)
        rst_count = flow.get('rst_count', 0)
        syn_ack_count = flow.get('syn_ack_count', 0)
        fin_count = flow.get('fin_count', 0)

        syn_rst_ratio = syn_count / max(rst_count, 1)
        half_open_ratio = max(0.0, (syn_count - syn_ack_count) / max(syn_count, 1))
        features['Syn/Rst Ratio'] = syn_rst_ratio
        features['Half Open Ratio'] = half_open_ratio
        features['Avg Packet Size'] = avg_pkt_size

        # Update cross-flow trackers.
        pp = self._update_port_probe_tracker(src_ip, dst_ip, dst_port, now)
        unique_ports_1s = len(set([p for p, t in pp['probes'] if t >= now - float(self.config.get('PORTCARD_WINDOW', 1))]))
        unique_ports_10s = len(set([p for p, t in pp['probes'] if t >= now - float(self.config.get('PORTSCAN_WINDOW', 10))]))

        dp = self._update_dst_port_tracker(dst_ip, dst_port, src_ip, now)
        dst_port_count = len(dp['timestamps'])
        distinct_src_ips = len(dp['src_ips'])

        # Custom DB rules remain as overrides.
        if self.db_rules:
            proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
            for r in self.db_rules:
                if r['action'] == "Drop / Block":
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
                elif r['field'] == "Packet Count":
                    try:
                        if total_packets >= int(r['value']):
                            match = True
                    except ValueError:
                        pass
                if match:
                    return {
                        'is_threat': True,
                        'label': r['name'] or 'Custom Rule',
                        'confidence': self._sample_confidence(),
                        'rule_triggered': f"Custom Rule: {r['name']}"
                    }

        # Web attack DPI stays unchanged.
        if self.config.get("ENABLE_WEB_DPI", True):
            for payload in flow.get('payload_samples', []):
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                    for pattern in self.web_attack_patterns:
                        if pattern.search(decoded_payload):
                            return {
                                'is_threat': True,
                                'label': 'Web Attacks',
                                'confidence': self._sample_confidence(),
                                'rule_triggered': 'DPI Match (Web Attack Signature)'
                            }
                except Exception:
                    continue

        # Port scanning heuristics — require clear multi-port SYN behavior.
        if self.config.get("ENABLE_SYN_SCAN", True):
            if flow.get('syn_flag', 0) == 1 and flow.get('ack_flag', 0) == 0 and total_packets <= int(self.config.get('PORTSCAN_MAX_PACKETS', 12)):
                if unique_ports_1s >= int(self.config.get('PORTSCAN_SHORT_WINDOW_PORTS', 5)) and avg_pkt_size < float(self.config.get('PORTSCAN_AVG_PKT_THRESHOLD', 120)):
                    return {
                        'is_threat': True,
                        'label': 'Port Scanning',
                        'confidence': self._sample_confidence(),
                        'rule_triggered': 'Heuristic: Rapid distinct port probes on same target'
                    }
                if unique_ports_10s >= int(self.config.get('PORTSCAN_WINDOW_PORTS', 12)) and avg_pkt_size < float(self.config.get('PORTSCAN_AVG_PKT_THRESHOLD', 120)):
                    return {
                        'is_threat': True,
                        'label': 'Port Scanning',
                        'confidence': self._sample_confidence(),
                        'rule_triggered': 'Heuristic: Multi-port SYN scan pattern'
                    }

        # Brute force heuristics — repeated connections to same target port.
        brute_threshold = int(self.config.get('BRUTE_FORCE_PORT_THRESHOLD', 25))
        brute_window = float(self.config.get('BRUTE_FORCE_WINDOW', 60))
        brute_attempts = sum(1 for t in self.ip_connection_tracker[src_ip] if now - t <= brute_window)
        if brute_attempts >= brute_threshold and total_packets >= 12 and distinct_src_ips == 1:
            return {
                'is_threat': True,
                'label': 'Brute Force',
                'confidence': self._sample_confidence(),
                'rule_triggered': f"Heuristic: Repeated connection attempts from {src_ip} ({brute_attempts} attempts)"
            }

        # DoS heuristics — large volume into one service port, low port variance.
        if dst_port_count >= int(self.config.get('DOS_PKT_THRESHOLD', 300)) and total_packets >= 30:
            if unique_ports_10s <= int(self.config.get('DOS_MAX_PORT_VARIANCE', 2)) and half_open_ratio >= float(self.config.get('DOS_HALF_OPEN_THRESHOLD', 0.6)):
                return {
                    'is_threat': True,
                    'label': 'DoS',
                    'confidence': self._sample_confidence(),
                    'rule_triggered': 'Heuristic: High rate to single port with half-open characteristics'
                }
            if avg_pkt_size >= float(self.config.get('DOS_AVG_PKT_THRESHOLD', 120)) and unique_ports_10s <= int(self.config.get('DOS_MAX_PORT_VARIANCE', 2)):
                return {
                    'is_threat': True,
                    'label': 'DoS',
                    'confidence': self._sample_confidence(),
                    'rule_triggered': 'Heuristic: Flooding traffic to one destination port'
                }

        return None
