# src/Interface/ui_components/style_constants.py
from tkinter import font as tkfont

COLORS = {
    'bg_darkest':   '#0a0e1a',
    'bg_dark':      '#111827',
    'bg_card':      '#1a2332',
    'bg_sidebar':   '#0f1629',
    'border':       '#1e293b',
    'border_light': '#2a3a52',
    'text_primary': '#e2e8f0',
    'text_secondary': '#94a3b8',
    'text_dim':     '#64748b',
    'accent_cyan':  '#00d4ff',
    'accent_red':   '#ef4444',
    'accent_amber': '#f59e0b',
    'accent_green': '#22c55e',
    'accent_blue':  '#3b82f6',
    'hover':        '#1e293b',
    'active_nav':   '#0c2d48',
    'btn_start':    '#166534',
    'btn_stop':     '#991b1b',
    'severity_high_bg':   '#3b1111',
    'severity_med_bg':    '#3b2a05',
    'severity_low_bg':    '#0a3b1a',
    'log_bg':       '#060b14',
}

SEVERITY_MAP = {
    'DDoS': 'High', 'DoS': 'High', 'Bots': 'High',
    'Brute Force': 'Medium', 'Port Scanning': 'Medium',
    'Web Attacks': 'Low',
}

SEVERITY_COLORS = {
    'High': COLORS['accent_red'],
    'Medium': COLORS['accent_amber'],
    'Low': COLORS['accent_green'],
}

def get_fonts():
    return {
        'brand':   ("Segoe UI", 16, "bold"),
        'nav':      ("Segoe UI", 11),
        'nav_bold': ("Segoe UI", 11, "bold"),
        'header':   ("Segoe UI", 12),
        'stat_num': ("Segoe UI", 28, "bold"),
        'stat_lbl': ("Segoe UI", 9),
        'stat_sub': ("Segoe UI", 8),
        'table':    ("Segoe UI", 9),
        'table_header': ("Segoe UI", 10, "bold"),
        'btn':      ("Segoe UI", 10, "bold"),
        'log':      ("Consolas", 9),
        'status':   ("Segoe UI", 9),
        'clock':    ("Consolas", 11),
    }
