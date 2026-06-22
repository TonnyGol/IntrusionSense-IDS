try:
    from net_utils import get_active_interface_name
except ImportError:
    from src.net_utils import get_active_interface_name

INTERFACE_NAME = get_active_interface_name()

ATTACK_LABELS = {
    0: 'Bots',
    1: 'Brute Force',
    2: 'DDoS',
    3: 'DoS',
    4: 'Port Scanning',
    5: 'Web Attacks'
}

# Database Credentials
DB_USER = "root"
DB_PASSWORD = "1234"
DB_HOST = "localhost"
DB_NAME = "intrusionsense"

# Heuristic Engine Configuration
HEURISTIC_CONFIG = {
    "ENABLE_WEB_DPI": True,
    "ENABLE_SYN_SCAN": True,
    "ENABLE_BRUTE_FORCE_RATE_LIMIT": True,
    "BRUTE_FORCE_MAX_CONNECTIONS": 20,
    "BRUTE_FORCE_TIME_WINDOW": 60 # seconds
}
