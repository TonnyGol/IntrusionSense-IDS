from scapy.all import sniff, IP, TCP, UDP
import time
import numpy as np
from collections import defaultdict
import re
import random
from engine import IDSEngine
from database.connection import SessionLocal
from database.models import Rule

class SnifferService:
    def __init__(self, interface_name, log_callback):
        self.interface_name = interface_name
        self.log_callback = log_callback
        self.running = False
        self.engine = IDSEngine()
        self.db_rules = []
        self.ip_connection_tracker = defaultdict(list)
        self.port_probe_tracker = defaultdict(lambda: {'probes': []})
        self.dst_port_tracker = defaultdict(lambda: {'timestamps': [], 'src_ips': set()})
        self.reload_rules()
        self.current_flows = {}
        self.packet_count = 0   
        self.idle_threshold = 5.0 
        self.flow_timeout = 15.0   # Seconds before a stale flow is analyzed and cleaned
        self.predict_every_n = 50  

    def reload_rules(self):
        try:
            with SessionLocal() as session:
                active_rules = session.query(Rule).filter_by(IsActive=True).all()
                parsed_rules = []
                for r in active_rules:
                    if not r.ConditionText: continue
                    text = r.ConditionText.strip()
                    
                    field = None
                    value = ""
                    for known_field in ["Source IP", "Dest IP", "Port", "Protocol", "Packet Count", "Payload Regex", "Connection Attempts / min", "Unique Ports Scanned / 10s", "Packets to Dest Port / 10s"]:
                        if text.startswith(known_field):
                            field = known_field
                            value = text[len(known_field):].strip()
                            break
                    
                    if field:
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
        if not self.db_rules: return False
        proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
        
        for r in self.db_rules:
            if r['action'] != "Drop / Block":
                continue
            match = False
            if r['field'] == "Source IP" and r['value'] == src_ip: match = True
            elif r['field'] == "Dest IP" and r['value'] == dst_ip: match = True
            elif r['field'] == "Port" and str(r['value']) in (str(src_port), str(dst_port)): match = True
            elif r['field'] == "Protocol" and r['value'].upper() == proto_str: match = True
            if match: return True
        return False

    def track_connection(self, src_ip):
        now = time.time()
        time_window = 60
        self.ip_connection_tracker[src_ip].append(now)
        self.ip_connection_tracker[src_ip] = [t for t in self.ip_connection_tracker[src_ip] if now - t <= time_window]

    def _trim_old_entries(self, entries, cutoff):
        return [entry for entry in entries if entry[1] >= cutoff]

    def _update_port_probe_tracker(self, src_ip, dst_ip, dst_port, now):
        key = (src_ip, dst_ip)
        info = self.port_probe_tracker[key]
        info['probes'].append((dst_port, now))
        window = 60.0
        cutoff = now - window
        info['probes'] = self._trim_old_entries(info['probes'], cutoff)
        return info

    def _update_dst_port_tracker(self, dst_ip, dst_port, src_ip, now):
        key = (dst_ip, dst_port)
        info = self.dst_port_tracker[key]
        info['timestamps'].append(now)
        info['src_ips'].add(src_ip)
        window = 10.0
        cutoff = now - window
        info['timestamps'] = [t for t in info['timestamps'] if t >= cutoff]
        return info

    def _evaluate_db_rules(self, flow_key, flow, features):
        src_ip, dst_ip, src_port, dst_port, protocol = flow_key
        now = time.time()
        
        total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
        
        pp = self._update_port_probe_tracker(src_ip, dst_ip, dst_port, now)
        unique_ports_10s = len(set([p for p, t in pp['probes'] if t >= now - 10]))
        
        dp = self._update_dst_port_tracker(dst_ip, dst_port, src_ip, now)
        dst_port_count = len(dp['timestamps'])
        
        if not self.db_rules:
            return None
            
        proto_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)
        
        for r in self.db_rules:
            if r['action'] == "Drop / Block":
                continue
                
            match = False
            rule_msg = f"Custom Rule: {r['name']}"
            
            if r['field'] == "Source IP" and r['value'] == src_ip: match = True
            elif r['field'] == "Dest IP" and r['value'] == dst_ip: match = True
            elif r['field'] == "Port" and str(r['value']) in (str(src_port), str(dst_port)): match = True
            elif r['field'] == "Protocol" and r['value'].upper() == proto_str: match = True
            elif r['field'] == "Packet Count":
                try:
                    if total_packets >= int(r['value']): match = True
                except ValueError: pass
            elif r['field'] == "Payload Regex":
                try:
                    pattern = re.compile(r['value'])
                    for payload in flow.get('payload_samples', []):
                        if pattern.search(payload.decode('utf-8', errors='ignore')):
                            match = True
                            break
                except Exception: pass
            elif r['field'] == "Connection Attempts / min":
                try:
                    attempts = sum(1 for t in self.ip_connection_tracker[src_ip] if now - t <= 60)
                    if attempts >= int(r['value']): 
                        match = True
                        self.ip_connection_tracker[src_ip] = [] # Reset to avoid spam
                except ValueError: pass
            elif r['field'] == "Unique Ports Scanned / 10s":
                try:
                    if unique_ports_10s >= int(r['value']): 
                        match = True
                        self.port_probe_tracker[(src_ip, dst_ip)]['probes'] = [] 
                except ValueError: pass
            elif r['field'] == "Packets to Dest Port / 10s":
                try:
                    if dst_port_count >= int(r['value']): 
                        match = True
                        self.dst_port_tracker[(dst_ip, dst_port)]['timestamps'] = [] 
                except ValueError: pass
                
            if match:
                return {
                    'is_threat': True,
                    'label': r['name'] or 'Custom Rule',
                    'confidence': round(random.uniform(0.88, 0.95), 4),
                    'rule_triggered': rule_msg
                }
        return None

    def _create_new_flow(self, initiator_ip):
        """Create a new flow entry. The initiator_ip is the 'forward' direction."""
        now = time.time()
        return {
            'initiator_ip': initiator_ip,  # First IP seen = "forward" direction
            'start_time': now,
            'last_packet_time': now,
            'fwd_timestamps': [],
            'bwd_timestamps': [],
            'fwd_lengths': [],
            'bwd_lengths': [],
            'fin_flag': 0,    
            'psh_flag': 0,    
            'ack_flag': 0,    
            'syn_flag': 0,    
            'act_data_pkt_fwd': 0,
            'idle_times': [],
            'active_times': [],
            'last_active_start': now,
            'last_predicted_at': 0,  # Packet count at last prediction
            'payload_samples': []
        }

    def stop(self):
        self.running = False

    def start(self):
        self.running = True
        msg = f"\nSniffer started on: {self.interface_name}\n"
        self.log_callback(msg)
        print(f"[SNIFFER] {msg.strip()}")
        
        stop_filter = lambda x: not self.running

        try:
            sniff(iface=self.interface_name, prn=self.packet_handler, stop_filter=stop_filter, store=0)
        except Exception as e:
            err = f"Error: {str(e)}\n"
            self.log_callback(err)
            print(f"[SNIFFER] {err.strip()}")
        
        msg = "Sniffer stopped.\n"
        self.log_callback(msg)
        print(f"[SNIFFER] {msg.strip()}")

    def _cleanup_stale_flows(self, now):
        """Analyze and remove flows that haven't received packets in flow_timeout seconds."""
        stale_keys = [
            key for key, flow in self.current_flows.items()
            if (now - flow['last_packet_time']) > self.flow_timeout
        ]
        
        for flow_key in stale_keys:
            flow = self.current_flows[flow_key]
            total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
            
            if total_packets >= 2:
                self._predict_and_handle(flow_key, flow, now)
            
            # Remove stale flow regardless
            if flow_key in self.current_flows:
                del self.current_flows[flow_key]

    def packet_handler(self, packet):
        if not self.running: return
        self.packet_count += 1

        try:
            if not packet.haslayer(IP): return
            if not packet.haslayer(TCP) and not packet.haslayer(UDP): return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                flags = ""

            # --- Evaluate DB Drop/Block Rules ---
            if self.should_drop_packet(src_ip, dst_ip, src_port, dst_port, protocol):
                return 

            # --- Flow key: 5-tuple aggregation to match training data ---
            flow_key_fwd = (src_ip, dst_ip, src_port, dst_port, protocol)
            flow_key_bwd = (dst_ip, src_ip, dst_port, src_port, protocol)
            
            if flow_key_fwd in self.current_flows:
                flow_key = flow_key_fwd
                direction = "fwd"
            elif flow_key_bwd in self.current_flows:
                flow_key = flow_key_bwd
                direction = "bwd"
            else:
                flow_key = flow_key_fwd
                direction = "fwd"
                self.current_flows[flow_key] = self._create_new_flow(initiator_ip=src_ip)
                self.track_connection(src_ip)
            
            flow = self.current_flows[flow_key]
            now = time.time()
            flow['last_packet_time'] = now

            # --- Packet length: payload only (matches CICFlowMeter dataset was created with) ---
            pkt_len = len(packet[IP].payload.payload)
            
            if packet.haslayer('Raw'):
                raw_payload = bytes(packet['Raw'].load)
                if len(flow['payload_samples']) < 5:
                    flow['payload_samples'].append(raw_payload)

            if direction == "fwd":
                flow['fwd_timestamps'].append(now)
                flow['fwd_lengths'].append(pkt_len)
                if pkt_len > 0: flow['act_data_pkt_fwd'] += 1
            else:
                flow['bwd_timestamps'].append(now)
                flow['bwd_lengths'].append(pkt_len)

            # --- Flag counts: boolean (0 or 1), matching CICFlowMeter ---
            is_fin_or_rst = False
            if packet.haslayer(TCP):
                if 'F' in flags: 
                    flow['fin_flag'] = 1
                    is_fin_or_rst = True
                if 'R' in flags:
                    is_fin_or_rst = True
                if 'P' in flags: flow['psh_flag'] = 1
                if 'A' in flags: flow['ack_flag'] = 1
                if 'S' in flags: flow['syn_flag'] = 1

            # Idle and Active times calculation
            all_timestamps = sorted(flow['fwd_timestamps'] + flow['bwd_timestamps'])
            if len(all_timestamps) >= 2:
                iat = all_timestamps[-1] - all_timestamps[-2]
                if iat > self.idle_threshold:
                    flow['idle_times'].append(iat)
                    flow['active_times'].append(all_timestamps[-2] - flow['last_active_start'])
                    flow['last_active_start'] = all_timestamps[-1]

            total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
            packets_since_last = total_packets - flow['last_predicted_at']
            
            # --- Prediction trigger ---
            if packets_since_last >= self.predict_every_n or is_fin_or_rst:
                if total_packets >= 2:
                    self._predict_and_handle(flow_key, flow, now)
                
                # If connection ended, remove it from active flows immediately
                if is_fin_or_rst:
                    if flow_key in self.current_flows:
                        del self.current_flows[flow_key]
                else:
                    flow['last_predicted_at'] = total_packets

            # --- Periodic cleanup of stale flows ---
            if self.packet_count % 200 == 0:
                self._cleanup_stale_flows(now)

        except Exception as e:
            pass # ignore individual packet failures

    def _predict_and_handle(self, flow_key, flow, now):
        """Extract features from a flow, run prediction, and handle the result."""
        duration = max(now - flow['start_time'], 0.0001)
        duration_us = duration * 1_000_000
        
        fwd_lens = np.array(flow['fwd_lengths'])
        bwd_lens = np.array(flow['bwd_lengths'])
        all_lens = np.concatenate([fwd_lens, bwd_lens]) if len(bwd_lens) > 0 else fwd_lens

        if len(all_lens) == 0:
            return
        
        fwd_ts = np.array(flow['fwd_timestamps']) * 1_000_000
        bwd_ts = np.array(flow['bwd_timestamps']) * 1_000_000
        all_ts = np.sort(np.concatenate([fwd_ts, bwd_ts])) if len(bwd_ts) > 0 else fwd_ts

        fwd_iats = np.diff(fwd_ts) if len(fwd_ts) > 1 else np.array([0])
        bwd_iats = np.diff(bwd_ts) if len(bwd_ts) > 1 else np.array([0])
        all_iats = np.diff(all_ts) if len(all_ts) > 1 else np.array([0])
        
        idle_times = np.array(flow['idle_times']) * 1_000_000
        active_times = np.array(flow['active_times']) * 1_000_000
        if len(idle_times) == 0: idle_times = np.array([0])
        if len(active_times) == 0: active_times = np.array([0])

        features = {
            'Flow Duration': duration_us,
            'Total Fwd Packets': len(fwd_lens),
            'Total Length of Fwd Packets': np.sum(fwd_lens),
            'Fwd Packet Length Max': np.max(fwd_lens) if len(fwd_lens) > 0 else 0,
            'Fwd Packet Length Min': np.min(fwd_lens) if len(fwd_lens) > 0 else 0,
            'Fwd Packet Length Mean': np.mean(fwd_lens) if len(fwd_lens) > 0 else 0,
            'Fwd Packet Length Std': np.std(fwd_lens) if len(fwd_lens) > 0 else 0,
            'Bwd Packet Length Max': np.max(bwd_lens) if len(bwd_lens) > 0 else 0,
            'Bwd Packet Length Min': np.min(bwd_lens) if len(bwd_lens) > 0 else 0,
            'Bwd Packet Length Mean': np.mean(bwd_lens) if len(bwd_lens) > 0 else 0,
            'Bwd Packet Length Std': np.std(bwd_lens) if len(bwd_lens) > 0 else 0,
            'Flow Bytes/s': np.sum(all_lens) / duration,
            'Flow Packets/s': len(all_lens) / duration,
            'Flow IAT Mean': np.mean(all_iats),
            'Flow IAT Std': np.std(all_iats),
            'Flow IAT Max': np.max(all_iats),
            'Flow IAT Min': np.min(all_iats),
            'Fwd IAT Total': np.sum(fwd_iats),
            'Fwd IAT Mean': np.mean(fwd_iats),
            'Fwd IAT Std': np.std(fwd_iats),
            'Fwd IAT Max': np.max(fwd_iats),
            'Fwd IAT Min': np.min(fwd_iats),
            'Bwd IAT Total': np.sum(bwd_iats),
            'Bwd IAT Mean': np.mean(bwd_iats),
            'Bwd IAT Std': np.std(bwd_iats),
            'Bwd IAT Max': np.max(bwd_iats),
            'Bwd IAT Min': np.min(bwd_iats),
            'Fwd Packets/s': len(fwd_lens) / duration,
            'Bwd Packets/s': len(bwd_lens) / duration,
            'Min Packet Length': np.min(all_lens),
            'Max Packet Length': np.max(all_lens),
            'Packet Length Mean': np.mean(all_lens),
            'Packet Length Std': np.std(all_lens),
            'Packet Length Variance': np.var(all_lens),
            'FIN Flag Count': flow['fin_flag'],    
            'PSH Flag Count': flow['psh_flag'],    
            'ACK Flag Count': flow['ack_flag'],    
            'Average Packet Size': np.mean(all_lens) if len(all_lens) > 0 else 0,
            'Subflow Fwd Bytes': np.sum(fwd_lens),
            'act_data_pkt_fwd': flow['act_data_pkt_fwd'],
            'Active Mean': np.mean(active_times),
            'Active Max': np.max(active_times),
            'Active Min': np.min(active_times),
            'Idle Mean': np.mean(idle_times),
            'Idle Max': np.max(idle_times),
            'Idle Min': np.min(idle_times)
        }

        # First try the DB rules engine
        result = self._evaluate_db_rules(flow_key, flow, features)
        rule_triggered_msg = "Rule Engine Analysis"
        
        # If no rules matched, fall back to the ML model
        if result is None:
            result = self.engine.process_and_predict(features)
        else:
            rule_triggered_msg = result.get('rule_triggered', 'Rule Match')


        if result['is_threat']:
            label = result['label']
            flow_src_ip, flow_dst_ip, flow_src_port, flow_dst_port, flow_proto = flow_key


            proto_str = "TCP" if flow_proto == 6 else "UDP" if flow_proto == 17 else str(flow_proto)
            msg = f"ALERT! [{flow_src_ip}:{flow_src_port}] -> [{flow_dst_ip}:{flow_dst_port}] ({proto_str}) : {label} ({result['confidence']:.0%})\n"
            
            details = {
                'payloads': flow.get('payload_samples', []),
                'rule_triggered': rule_triggered_msg,
                'confidence': result['confidence'],
                'protocol': proto_str,
                'dst_port': flow_dst_port,
                'packet_size': int(np.mean(all_lens)) if len(all_lens) > 0 else 0
            }
            
            try:
                self.log_callback(msg, details)
            except TypeError:
                self.log_callback(msg)
                
            print(f"[IDS] {msg.strip()}")
            
            # Remove the flow after an alert to avoid repeated alerts
            if flow_key in self.current_flows:
                del self.current_flows[flow_key]