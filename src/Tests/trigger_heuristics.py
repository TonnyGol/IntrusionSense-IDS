import urllib.request
import urllib.error
import threading
import time

def trigger_web_attack():
    print("[*] Triggering Web Attack (SQLi Payload)...")
    url = "http://example.com/?query=UNION+SELECT"
    try:
        # We don't care about the response, just sending the packet over HTTP
        urllib.request.urlopen(url, timeout=2)
    except Exception:
        pass
    print("[+] Web Attack packet sent! Check your dashboard.\n")


def trigger_brute_force():
    print("[*] Triggering Brute Force Rate Limit (Opening 25 connections)...")
    
    def fetch():
        try:
            urllib.request.urlopen("http://example.com", timeout=2)
        except Exception:
            pass

    threads = []
    for _ in range(25):
        t = threading.Thread(target=fetch)
        t.start()
        threads.append(t)
        time.sleep(0.05) # slight delay so sniffer groups them correctly
        
    for t in threads:
        t.join()
        
    print("[+] 25 connections opened! Check your dashboard for Brute Force alert.\n")


def trigger_syn_scan():
    print("[*] Triggering Stealth SYN Scan...")
    try:
        from scapy.all import IP, TCP, send
        # Send 2 pure SYN packets to an external IP
        packet = IP(dst="8.8.8.8")/TCP(dport=[80, 443], flags="S")
        send(packet, verbose=False)
        print("[+] SYN packets sent! Check your dashboard for Port Scanning alert.\n")
    except ImportError:
        print("[-] Scapy not found. Please run this script in your IDS Python environment.")
    except Exception as e:
        print(f"[-] Error sending raw packet: {e}")
        print("Note: Sending raw packets on Windows might require running the terminal as Administrator.")


if __name__ == "__main__":
    print("=== IntrusionSense Heuristics Tester ===\n")
    
    trigger_web_attack()
    time.sleep(2)
    
    trigger_brute_force()
    time.sleep(2)
    
    trigger_syn_scan()
    print("=== Testing Complete ===")
