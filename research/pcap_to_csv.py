import sys
import os
import csv
import time
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP

def create_new_flow(packet_time):
    return {
        'start_time': packet_time,
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
        'last_active_start': packet_time
    }

def process_pcap(pcap_file, output_csv):
    idle_threshold = 5.0
    current_flows = {}
    extracted_features_list = []
    
    print(f"[*] Reading PCAP: {pcap_file}")
    
    try:
        reader = PcapReader(pcap_file)
    except FileNotFoundError:
        print(f"[!] File not found: {pcap_file}")
        return

    packet_count = 0
    
    for packet in reader:
        packet_count += 1
        if packet_count % 10000 == 0:
            print(f"  -> Processed {packet_count} packets...")

        if not packet.haslayer(IP): continue
        if not packet.haslayer(TCP) and not packet.haslayer(UDP): continue

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_time = float(packet.time)
        pkt_len = len(packet)
        
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
        
        if flow_key_fwd in current_flows:
            flow_key = flow_key_fwd
            direction = "fwd"
        elif flow_key_bwd in current_flows:
            flow_key = flow_key_bwd
            direction = "bwd"
        else:
            flow_key = flow_key_fwd
            direction = "fwd"
            current_flows[flow_key] = create_new_flow(packet_time)
        
        flow = current_flows[flow_key]

        if direction == "fwd":
            flow['fwd_timestamps'].append(packet_time)
            flow['fwd_lengths'].append(pkt_len)
            if pkt_len > 0: flow['act_data_pkt_fwd'] += 1
        else:
            flow['bwd_timestamps'].append(packet_time)
            flow['bwd_lengths'].append(pkt_len)

        if packet.haslayer(TCP):
            if 'F' in flags: flow['fin_count'] += 1
            if 'P' in flags: flow['psh_count'] += 1
            if 'A' in flags: flow['ack_count'] += 1

        # Idle and Active times
        all_timestamps = sorted(flow['fwd_timestamps'] + flow['bwd_timestamps'])
        if len(all_timestamps) >= 2:
            iat = all_timestamps[-1] - all_timestamps[-2]
            if iat > idle_threshold:
                flow['idle_times'].append(iat)
                flow['active_times'].append(all_timestamps[-2] - flow['last_active_start'])
                flow['last_active_start'] = all_timestamps[-1]

        total_packets = len(flow['fwd_lengths']) + len(flow['bwd_lengths'])
        
        # Predict on reaching a chunk of 100 packets or connection finish
        if total_packets % 100 == 0 or 'F' in flags:
            duration = max(packet_time - flow['start_time'], 0.0001)
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
                'Destination Port': dst_port if direction == 'fwd' else src_port,
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
                'Idle Min': np.min(idle_times),
                'Attack Type': 'Normal Traffic' # Force label to Normal Traffic for custom PCAPs
            }
            extracted_features_list.append(features)
            
            # If flow ended with FIN, clear it from memory to mimic sniffer
            if 'F' in flags:
                del current_flows[flow_key]

    print(f"[*] Finished reading PCAP. Extracted {len(extracted_features_list)} flow chunks.")
    
    if len(extracted_features_list) > 0:
        print(f"[*] Writing to {output_csv}...")
        headers = list(extracted_features_list[0].keys())
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in extracted_features_list:
                writer.writerow(row)
        print(f"[OK] Saved {len(extracted_features_list)} rows to {output_csv}")
    else:
        print("[!] No flows extracted.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pcap_to_csv.py <input.pcap> <output.csv>")
        sys.exit(1)
        
    pcap_in = sys.argv[1]
    csv_out = sys.argv[2]
    
    process_pcap(pcap_in, csv_out)
