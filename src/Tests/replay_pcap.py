import sys
import os
import time

# Add parent directory to path so we can import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sendp
from scapy.utils import PcapReader
from net_utils import get_active_interface_name

def replay_traffic(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"[ERROR] Could not find file: {pcap_path}")
        return

    iface = get_active_interface_name()
    print(f"[*] Loading network traffic from {pcap_path}...")
    
    try:
        print(f"[*] Streaming and replaying packets over interface [{iface}]...")
        count = 0
        
        # Using PcapReader instead of rdpcap allows us to stream large files (>170MB)
        # without running out of RAM, because it only loads one packet at a time.
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                sendp(pkt, iface=iface, verbose=0)
                count += 1
                if count % 1000 == 0:
                    print(f"    -> Sent {count} packets so far...")
                # Slight inter-packet delay to not overwhelm the adapter
                time.sleep(0.001)
                
        print(f"[*] Replay complete! Total packets sent: {count}")
        
    except Exception as e:
        print(f"[ERROR] Failed to replay packets: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python replay_pcap.py <path_to_pcap_file>")
        print("Example: python replay_pcap.py sample_attack.pcap")
    else:
        replay_traffic(sys.argv[1])
