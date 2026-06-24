import socket
import threading
import time

TARGET_IP = "1.1.1.1" # Cloudflare IPv4 (guaranteed to respond to ping/HTTP)

def trigger_web_attack():
    print("[*] Triggering 3 Web Attacks (SQLi, Auth Bypass, XSS)...")
    payloads = [
        b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\nUNION SELECT * FROM users;",
        b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin' OR '1'='1",
        b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n<script>alert('XSS')</script>"
    ]
    
    for i, payload in enumerate(payloads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET_IP, 80))
            s.sendall(payload)
            s.close()
            time.sleep(0.5) # Slight delay between attacks
        except Exception as e:
            print(f"[-] Web attack {i+1} failed: {e}")
            
    print("[+] 3 Web Attack packets sent! Check your dashboard.\n")


def trigger_brute_force():
    print("[*] Triggering Brute Force Rate Limit (Opening 30 connections)...")
    
    def fetch():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET_IP, 80))
            s.close()
        except Exception:
            pass

    threads = []
    for _ in range(30):
        t = threading.Thread(target=fetch)
        t.start()
        threads.append(t)
        time.sleep(0.02) # slight delay to stagger packets
        
    for t in threads:
        t.join()
        
    print("[+] 30 connections opened! Check your dashboard for Brute Force alert.\n")


def trigger_port_scan():
    print("[*] Triggering Port Scan (Scanning 15 unique ports via UDP)...")
    
    # We use UDP to easily blast packets without needing handshakes or OS responses.
    # We send 55 packets to each port to force the IDS to hit its prediction threshold.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in range(8000, 8015):
        for _ in range(55):
            try:
                s.sendto(b"ping", (TARGET_IP, port))
            except:
                pass
        time.sleep(0.01)
        
    s.close()
    print("[+] UDP Port Scan complete! Check your dashboard for Port Scanning alert.\n")


def trigger_dos():
    print("[*] Triggering DoS (Sending 350 rapid sequential connection attempts)...")
    
    # Use a single loop rather than 350 threads to avoid hitting OS socket limits.
    for i in range(350):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, 80))
            s.close()
        except Exception:
            pass
        if i % 50 == 0:
            time.sleep(0.01) 
            
    print("[+] 350 connection attempts made! Check your dashboard for DoS alert.\n")


if __name__ == "__main__":
    print("=== IntrusionSense Rules Tester (IPv4 Socket Mode) ===\n")
    
    trigger_web_attack()
    time.sleep(2)
    
    trigger_brute_force()
    time.sleep(2)
    
    trigger_port_scan()
    time.sleep(2)
    
    trigger_dos()
    print("\n=== Testing Complete ===")
