# src/Interface/sniffer_service.py
from scapy.all import sniff, IP, TCP, UDP
import time
import numpy as np
import requests
from collections import defaultdict
from engine import IDSEngine

class SnifferService:
    def __init__(self, interface_name, log_callback):
        self.interface_name = interface_name
        self.log_callback = log_callback
        self.running = False
        self.engine = IDSEngine()
        self.current_flows = {}
        self.packet_count = 0   # Total packets seen (polled by dashboard)
        self.idle_threshold = 5.0  # 5 seconds threshold for Idle/Active times


    def _create_new_flow(self):
        now = time.time()
        return {
            'start_time': now,
            'fwd_timestamps': [],
            'bwd_timestamps': [],
            'fwd_lengths': [],
            'bwd_lengths': [],
            'fin_count': 0,
            'psh_count': 0,
            'ack_count': 0,
            'act_data_pkt_fwd': 0,
            'idle_times': [],
            'active_times': [],
            'last_active_start': now
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
                self.current_flows[flow_key] = self._create_new_flow()
            
            flow = self.current_flows[flow_key]
            pkt_len = len(packet)
            now = time.time()

            if direction == "fwd":
                flow['fwd_timestamps'].append(now)
                flow['fwd_lengths'].append(pkt_len)
                if pkt_len > 0: flow['act_data_pkt_fwd'] += 1
            else:
                flow['bwd_timestamps'].append(now)
                flow['bwd_lengths'].append(pkt_len)

            if packet.haslayer(TCP):
                if 'F' in flags: flow['fin_count'] += 1
                if 'P' in flags: flow['psh_count'] += 1
                if 'A' in flags: flow['ack_count'] += 1

            # Idle and Active times calculation
            all_timestamps = sorted(flow['fwd_timestamps'] + flow['bwd_timestamps'])
            if len(all_timestamps) >= 2:
                iat = all_timestamps[-1] - all_timestamps[-2]
                if iat > self.idle_threshold:
                    flow['idle_times'].append(iat)
                    flow['active_times'].append(all_timestamps[-2] - flow['last_active_start'])
                    flow['last_active_start'] = all_timestamps[-1]

            total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
            
            # Predict on reaching a flow chunk of 100 packets, or upon connection finish (FIN/RST)
            if total_packets % 100 == 0 or 'F' in flags or 'R' in flags:
                duration = max(now - flow['start_time'], 0.0001)
                duration_us = duration * 1_000_000
                
                fwd_lens = np.array(flow['fwd_lengths'])
                bwd_lens = np.array(flow['bwd_lengths'])
                all_lens = np.concatenate([fwd_lens, bwd_lens]) if len(bwd_lens) > 0 else fwd_lens
                
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
                    'FIN Flag Count': flow['fin_count'],
                    'PSH Flag Count': flow['psh_count'],
                    'ACK Flag Count': flow['ack_count'],
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

                result = self.engine.process_and_predict(features)
                
                # --- DEBUG PRINT TO SEE LAYER 2 DECISION ---
                #print(f"[DEBUG] Layer 2 analyzed flow from {flow_key[0]}:{flow_key[2]} -> {flow_key[1]}:{flow_key[3]}")
                #print(f"        -> Decision: {result['label']} (Confidence: {result['confidence']:.0%})")

                if result['is_threat']:
                    label = result['label']
                    flow_src_ip, flow_dst_ip, flow_src_port, flow_dst_port, _ = flow_key
                    
                    if label == "Web Attacks":
                        # We are explicitly ignoring Web Attacks because flow-based models
                        # are highly prone to false positives on bursty web traffic.
                        del self.current_flows[flow_key]
                        return

                    msg = f"ALERT! [{flow_src_ip}] -> [{flow_dst_ip}] : {label} ({result['confidence']:.0%})\n"
                    self.log_callback(msg)
                    print(f"[IDS] {msg.strip()}")
                    
                    del self.current_flows[flow_key]

        except Exception as e:
            pass # Keep it fast, ignore individual packet failures