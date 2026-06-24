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
    "BRUTE_FORCE_TIME_WINDOW": 60, # seconds
    "BRUTE_FORCE_PORT_THRESHOLD": 25,
    "BRUTE_FORCE_WINDOW": 60,
    "PORTSCAN_WINDOW": 60,
    "PORTCARD_WINDOW": 1,
    "PORTSCAN_SHORT_WINDOW_PORTS": 5,
    "PORTSCAN_WINDOW_PORTS": 12,
    "PORTSCAN_AVG_PKT_THRESHOLD": 120,
    "DOS_WINDOW": 10,
    "DOS_PKT_THRESHOLD": 300,
    "DOS_HALF_OPEN_THRESHOLD": 0.6,
    "DOS_MAX_PORT_VARIANCE": 2,
    "DOS_AVG_PKT_THRESHOLD": 120
}
