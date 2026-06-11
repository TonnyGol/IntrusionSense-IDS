try:
    from net_utils import get_active_interface_name
except ImportError:
    from src.net_utils import get_active_interface_name

INTERFACE_NAME = get_active_interface_name()

# הגדרת שמות ההתקפות
ATTACK_LABELS = {
    0: 'Bots',
    1: 'Brute Force',
    2: 'DDoS',
    3: 'DoS',
    4: 'Normal Traffic',
    5: 'Port Scanning',
    6: 'Web Attacks'
}

