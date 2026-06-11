import time
import socket
import threading
from scapy.all import IP, TCP, UDP, send, RandShort

# Get local IP to attack
hostname = socket.gethostname()
LOCAL_IP = socket.gethostbyname(hostname)

def simulate_dos():
    print(f"\n[*] Launching DoS SYN Flood against {LOCAL_IP}...")
    print("[*] (Make sure the Dashboard Sniffer is RUNNING!)")
    
    # We send 200 packets in the exact same flow to trigger the 100-packet analysis chunk
    # in sniffer_service.py
    src_port = 12345
    dst_port = 80
    
    for i in range(250):
        pkt = IP(src="10.0.0.99", dst=LOCAL_IP)/TCP(sport=src_port, dport=dst_port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.005) # Add a tiny delay so the flow has some 'Duration' and 'IAT'
        
    print("[+] DoS Attack completed!")

def simulate_port_scan():
    print(f"\n[*] Launching Port Scan against {LOCAL_IP}...")
    print("[*] (Make sure the Dashboard Sniffer is RUNNING!)")
    
    # We send SYN followed by FIN to multiple ports. 
    # The FIN flag immediately forces sniffer_service.py to run a prediction on that flow.
    for port in range(20, 120):
        # Send SYN
        pkt_syn = IP(src="10.0.0.100", dst=LOCAL_IP)/TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt_syn, verbose=0)
        
        # Send FIN to close the flow and force prediction
        pkt_fin = IP(src="10.0.0.100", dst=LOCAL_IP)/TCP(sport=pkt_syn[TCP].sport, dport=port, flags="F")
        send(pkt_fin, verbose=0)
        
        time.sleep(0.02)
        
    print("[+] Port Scan completed!")

def simulate_brute_force():
    print(f"\n[*] Launching Brute Force (SSH/FTP) against {LOCAL_IP}...")
    print("[*] (Make sure the Dashboard Sniffer is RUNNING!)")
    
    # Send repeated data packets (like password guesses) to Port 22
    src_port = int(RandShort())
    for i in range(120):
        # PSH+ACK flags with a payload simulating a login attempt
        pkt = IP(src="10.0.0.101", dst=LOCAL_IP)/TCP(sport=src_port, dport=22, flags="PA")/"LOGIN_ATTEMPT_DATA"
        send(pkt, verbose=0)
        time.sleep(0.05)
        
    print("[+] Brute Force Attack completed!")

if __name__ == "__main__":
    while True:
        print("\n" + "="*40)
        print("      LIVE IDS DEMO ATTACK SCRIPT")
        print("="*40)
        print(f"Targeting Local Machine: {LOCAL_IP}")
        print("1. Simulate DoS (SYN Flood)")
        print("2. Simulate Port Scanning")
        print("3. Simulate Brute Force (SSH/FTP)")
        print("4. Exit")
        
        choice = input("\nSelect an attack to run: ")
        
        if choice == '1':
            simulate_dos()
        elif choice == '2':
            simulate_port_scan()
        elif choice == '3':
            simulate_brute_force()
        elif choice == '4':
            break
        else:
            print("[!] Invalid choice. Try again.")
