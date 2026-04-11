try:
    from net_utils import get_active_interface_name
except ImportError:
    from src.net_utils import get_active_interface_name

INTERFACE_NAME = get_active_interface_name()

# הגדרת שמות ההתקפות
ATTACK_LABELS = {
    0: 'BENIGN (Safe)',
    1: 'DoS Attack',
    2: 'PortScan',
    3: 'BruteForce',
    4: 'WebAttack'
}