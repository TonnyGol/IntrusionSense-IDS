# src/find_adapter.py
from scapy.all import get_if_list, get_if_hwaddr, show_interfaces

print("--- Network Interfaces Found ---")
show_interfaces()

print("\n--- Simple List ---")
for iface in get_if_list():
    try:
        print(f"Interface: {iface}")
    except:
        pass