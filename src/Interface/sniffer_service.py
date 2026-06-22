# src/Interface/sniffer_service.py
from scapy.all import sniff, IP, TCP, UDP
import time
import numpy as np
import requests
from collections import defaultdict
from engine import IDSEngine
from heuristic_engine import HeuristicEngine

class SnifferService:
    def __init__(self, interface_name, log_callback):
        self.interface_name = interface_name
        self.log_callback = log_callback
        self.running = False
        self.engine = IDSEngine()
        self.heuristic_engine = HeuristicEngine()
        self.current_flows = {}
        self.packet_count = 0   # Total packets seen (polled by dashboard)
        self.idle_threshold = 5.0  # 5 seconds threshold for Idle/Active times
        self.flow_timeout = 15.0   # Seconds before a stale flow is analyzed and cleaned
        self.predict_every_n = 50  # Predict every N packets in a flow


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
            'fin_flag': 0,    # Boolean: was FIN flag seen? (0 or 1)
            'psh_flag': 0,    # Boolean: was PSH flag seen? (0 or 1)
            'ack_flag': 0,    # Boolean: was ACK flag seen? (0 or 1)
            'syn_flag': 0,    # Boolean: was SYN flag seen? (0 or 1)
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
            
            # Only predict if there's enough data (at least 2 packets)
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
            if self.heuristic_engine.should_drop_packet(src_ip, dst_ip, src_port, dst_port, protocol):
                return # Silently ignore!

            # --- Flow key: 5-tuple aggregation matching training data ---
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
                self.heuristic_engine.track_connection(src_ip)
            
            flow = self.current_flows[flow_key]
            now = time.time()
            flow['last_packet_time'] = now

            # --- Packet length: payload only (matches CICFlowMeter) ---
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
            
            # --- Prediction trigger: every N packets, or on FIN/RST termination ---
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
            pass # Keep it fast, ignore individual packet failures

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
            'FIN Flag Count': flow['fin_flag'],    # Boolean 0/1
            'PSH Flag Count': flow['psh_flag'],    # Boolean 0/1
            'ACK Flag Count': flow['ack_flag'],    # Boolean 0/1
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

        # First try the heuristic engine
        result = self.heuristic_engine.evaluate_flow(flow_key, flow, features)
        rule_triggered_msg = "Machine Learning Model Analysis"
        
        # If no heuristic matched, fall back to the ML model
        if result is None:
            result = self.engine.process_and_predict(features)
        else:
            rule_triggered_msg = result.get('rule_triggered', 'Heuristic Match')


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