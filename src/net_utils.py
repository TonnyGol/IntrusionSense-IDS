# src/net_utils.py
# Shared network utilities for attack simulation and dashboard
import socket
import psutil


def get_active_interface_name():
    """Auto-detect the active network interface name."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        active_ip = s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

    interfaces = psutil.net_if_addrs()
    for interface_name, addresses in interfaces.items():
        for address in addresses:
            if address.family == socket.AF_INET and address.address == active_ip:
                return interface_name
    return None


def get_default_gateway():
    """Get the default gateway IP (router). Traffic to this IP always goes
    through the physical interface, so the sniffer will see it."""
    try:
        # Get our local IP first
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume gateway is .1 on the same subnet (works for most home/office networks)
        parts = local_ip.rsplit('.', 1)
        return parts[0] + '.1'
    except Exception:
        return "8.8.8.8"  # Fallback to Google DNS

