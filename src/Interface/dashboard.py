import sys
import os
import json

# --- Path Fix (must be first!) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import tkinter as tk
from tkinter import ttk, font as tkfont
import threading
import time
from datetime import datetime
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sniffer_service import SnifferService
from net_utils import get_active_interface_name
import config
from database.connection import session
from database.models import Rule, Alert, TrafficLog

INTERFACE_NAME = get_active_interface_name()

# ══════════════════════════════════════════════════════════════
#  COLOR PALETTE
# ══════════════════════════════════════════════════════════════
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

# Map attack types to severity
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


class IDSDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("IntrusionSense — IDS Dashboard")
        self.root.geometry("1280x780")
        self.root.minsize(1100, 650)
        self.root.configure(bg=COLORS['bg_darkest'])

        # State
        self.sniffer_thread = None
        self.sniffer_service = None
        self.is_sniffing = False
        self.alerts = []          # list of dicts
        self.packets_analyzed = 0
        self.stats = {'total': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        self.model_loaded = False

        self.historical_logs = []
        self._load_historical_logs()
        
        self.rules = []
        self._load_rules()

        # Fonts
        self.font_brand   = ("Segoe UI", 16, "bold")
        self.font_nav      = ("Segoe UI", 11)
        self.font_nav_bold = ("Segoe UI", 11, "bold")
        self.font_header   = ("Segoe UI", 12)
        self.font_stat_num = ("Segoe UI", 28, "bold")
        self.font_stat_lbl = ("Segoe UI", 9)
        self.font_stat_sub = ("Segoe UI", 8)
        self.font_table    = ("Segoe UI", 9)
        self.font_table_header = ("Segoe UI", 9, "bold")
        self.font_log      = ("Consolas", 9)
        self.font_status   = ("Segoe UI", 9)
        self.font_btn      = ("Segoe UI", 10, "bold")
        self.font_clock    = ("Consolas", 11)

        self.alert_counts = {}
        self.detailed_alerts = []

        self.container = tk.Frame(self.root, bg=COLORS['bg_darkest'])
        self.container.pack(fill=tk.BOTH, expand=True)

        self.frame_login = tk.Frame(self.container, bg=COLORS['bg_darkest'])
        self.frame_main = tk.Frame(self.container, bg=COLORS['bg_darkest'])

        self._build_login()
        self._build_ui(self.frame_main)
        
        self.frame_login.pack(fill=tk.BOTH, expand=True)
        self._tick_clock()
        self.root.bind("<Button-1>", self._clear_tree_selection)

    def _clear_tree_selection(self, event):
        widget = event.widget
        w_class = widget.winfo_class()
        
        if w_class in ['Treeview', 'Scrollbar']:
            return
            
        if hasattr(self, 'btn_scan') and widget == self.btn_scan:
            return
            
        if hasattr(self, 'tree'):
            try:
                self.tree.selection_remove(self.tree.selection())
            except Exception: pass
        if hasattr(self, 'hist_tree'):
            try:
                self.hist_tree.selection_remove(self.hist_tree.selection())
            except Exception: pass

    def _build_login(self):
        box = tk.Frame(self.frame_login, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1, padx=40, pady=40)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        brand_frame = tk.Frame(box, bg=COLORS['bg_card'], width=200, height=40)
        brand_frame.pack(pady=(0, 5))
        brand_frame.pack_propagate(False)

        tk.Label(brand_frame, text="🛡️", font=("Segoe UI", 20),
                 bg=COLORS['bg_card'], fg=COLORS['accent_cyan']).place(x=12, rely=0.5, anchor=tk.W)
        tk.Label(brand_frame, text="IntrusionSense", font=self.font_brand,
                 bg=COLORS['bg_card'], fg=COLORS['accent_cyan']).place(x=46, rely=0.5, anchor=tk.W)
        tk.Label(box, text="Admin Authentication", font=self.font_header, bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(pady=(0, 30))

        tk.Label(box, text="Username", font=self.font_stat_lbl, bg=COLORS['bg_card'], fg=COLORS['text_dim']).pack(anchor=tk.W)
        self.ent_user = tk.Entry(box, font=self.font_header, bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT)
        self.ent_user.pack(fill=tk.X, pady=(5, 15), ipady=5)

        tk.Label(box, text="Password", font=self.font_stat_lbl, bg=COLORS['bg_card'], fg=COLORS['text_dim']).pack(anchor=tk.W)
        self.ent_pass = tk.Entry(box, font=self.font_header, bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT, show="*")
        self.ent_pass.pack(fill=tk.X, pady=(5, 25), ipady=5)

        self.lbl_login_err = tk.Label(box, text="", font=self.font_stat_lbl, bg=COLORS['bg_card'], fg=COLORS['accent_red'])
        self.lbl_login_err.pack(pady=(0, 10))

        btn = tk.Button(box, text="Login to Command Center", font=self.font_btn, bg=COLORS['accent_blue'], fg="white", relief=tk.FLAT, cursor="hand2", command=self._do_login)
        btn.pack(fill=tk.X, ipady=8)

    def _do_login(self):
        username = self.ent_user.get()
        pwd = self.ent_pass.get()
        
        import hashlib
        hashed_pwd = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
        
        from database.models import User
        from database.connection import session
        
        user = session.query(User).filter_by(Username=username).first()
        
        if user and user.PasswordHash == hashed_pwd:
            self.lbl_login_err.config(text="")
            self.current_user = user
            self.current_role = user.Role
            self.frame_login.pack_forget()
            
            self._apply_rbac()
            self.frame_main.pack(fill=tk.BOTH, expand=True)
        else:
            self.lbl_login_err.config(text="Invalid credentials")

    def _apply_rbac(self):
        # Hide Settings for Manager and SOC Analyst
        if self.current_role in ["Manager", "SOC Analyst"]:
            for container, label in self.nav_buttons:
                if label == "Settings":
                    container.pack_forget()
                    
        # Disable Rules editing for SOC Analyst
        if self.current_role == "SOC Analyst":
            if hasattr(self, 'rules_control_frame') and self.rules_control_frame:
                for child in self.rules_control_frame.winfo_children():
                    try:
                        child['state'] = tk.DISABLED
                    except Exception:
                        pass

    def _do_logout(self):
        # Reset current user state
        self.current_user = None
        self.current_role = None
        
        # Restore RBAC-hidden elements
        for container, label in self.nav_buttons:
            if label == "Settings":
                # Restore the Settings nav button
                container.pack(fill=tk.X, pady=2)
                
        if hasattr(self, 'rules_control_frame') and self.rules_control_frame:
            for child in self.rules_control_frame.winfo_children():
                try:
                    child['state'] = tk.NORMAL
                except Exception:
                    pass
            
        # Switch to Dashboard view by default
        self._switch_view("Dashboard")
        
        # Clear login form
        self.ent_pass.delete(0, tk.END)
        self.lbl_login_err.config(text="")
        
        # Switch to login screen
        self.frame_main.pack_forget()
        self.frame_login.pack(fill=tk.BOTH, expand=True)
    # ══════════════════════════════════════════════════════════
    #  BUILD UI
    # ══════════════════════════════════════════════════════════
    def _build_ui(self, parent):
        # ── Sidebar ──────────────────────────────────────────
        self.sidebar = tk.Frame(parent, bg=COLORS['bg_sidebar'], width=240)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        self._build_sidebar()

        # ── Main Area ────────────────────────────────────────
        self.main_area = tk.Frame(parent, bg=COLORS['bg_darkest'])
        self.main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.frame_dashboard = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_historical = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_traffic_monitor = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_rules = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])

        self._build_dashboard_ui(self.frame_dashboard)
        self._build_historical_ui(self.frame_historical)
        self._build_traffic_monitor_ui(self.frame_traffic_monitor)
        self._build_rules_ui(self.frame_rules)

        self.frame_dashboard.pack(fill=tk.BOTH, expand=True)
        self.current_view = "Dashboard"

    def _build_dashboard_ui(self, main):
        self._build_header(main)
        self._build_stat_cards(main)

        middle = tk.Frame(main, bg=COLORS['bg_darkest'])
        middle.pack(fill=tk.BOTH, expand=True)

        table_area = tk.Frame(middle, bg=COLORS['bg_darkest'])
        table_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        chart_area = tk.Frame(middle, bg=COLORS['bg_darkest'])
        chart_area.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(0, 15), pady=(0, 6))

        self._build_alerts_table(table_area)
        self._build_chart(chart_area)
        self._build_log_panel(main)

    # ─────────────────────────────────────────────────────────
    #  SIDEBAR
    # ─────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = self.sidebar

        # Brand
        brand_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'], width=200, height=40)
        brand_frame.pack(pady=(20, 30))
        brand_frame.pack_propagate(False)
        
        tk.Label(brand_frame, text="🛡️", font=("Segoe UI", 20),
                 bg=COLORS['bg_sidebar'], fg=COLORS['accent_cyan']).place(x=20, rely=0.5, anchor=tk.W)
        tk.Label(brand_frame, text="IntrusionSense", font=("Segoe UI", 14, "bold"),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_primary']).place(x=54, rely=0.5, anchor=tk.W)

        # Navigation
        nav_items = [
            ("📊", "Dashboard", True),
            ("📝", "Rules", False),
            ("📡", "Traffic Monitor", False),
            ("📋", "Historical Logs", False),
            ("⚙️", "Settings", False),
        ]
        self.nav_buttons = []
        for icon, label, active in nav_items:
            btn = self._create_nav_button(sb, icon, label, active)
            if label == "Settings":
                btn.bind("<Button-1>", self._open_settings)
                # Ensure children of btn (like label and accent) also trigger setting open
                for child in btn.winfo_children():
                    child.bind("<Button-1>", self._open_settings)
            elif label in ["Dashboard", "Historical Logs", "Traffic Monitor", "Rules"]:
                btn.bind("<Button-1>", lambda e, l=label: self._switch_view(l))
                for child in btn.winfo_children():
                    child.bind("<Button-1>", lambda e, l=label: self._switch_view(l))
            self.nav_buttons.append((btn, label))

        # Spacer
        tk.Frame(sb, bg=COLORS['bg_sidebar']).pack(fill=tk.BOTH, expand=True)

        # Logout Button
        logout_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'])
        logout_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        tk.Button(logout_frame, text="🚪 Logout", font=self.font_btn, bg=COLORS['border'], fg=COLORS['text_primary'],
                  relief=tk.FLAT, cursor="hand2", command=self._do_logout).pack(fill=tk.X, ipady=4)

        # ── System Status ────────────────────────────────────
        status_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'])
        status_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        tk.Label(status_frame, text="System Status", font=("Segoe UI", 10, "bold"),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=(0, 8))

        # Sniffer status
        row_sniff = tk.Frame(status_frame, bg=COLORS['bg_sidebar'])
        row_sniff.pack(fill=tk.X, pady=2)
        tk.Label(row_sniff, text="Sniffer:", font=self.font_status,
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(side=tk.LEFT)
        self.lbl_sniffer_status = tk.Label(row_sniff, text="● Stopped", font=self.font_status,
                                           bg=COLORS['bg_sidebar'], fg=COLORS['accent_red'])
        self.lbl_sniffer_status.pack(side=tk.RIGHT)

        # Model status
        row_model = tk.Frame(status_frame, bg=COLORS['bg_sidebar'])
        row_model.pack(fill=tk.X, pady=2)
        tk.Label(row_model, text="ML Model:", font=self.font_status,
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(side=tk.LEFT)
        self.lbl_model_status = tk.Label(row_model, text="● Not Loaded", font=self.font_status,
                                         bg=COLORS['bg_sidebar'], fg=COLORS['text_dim'])
        self.lbl_model_status.pack(side=tk.RIGHT)

        # Version
        tk.Label(status_frame, text="Version 1.0.0", font=("Segoe UI", 8),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(anchor=tk.W, pady=(10, 0))

    def _open_settings(self, event=None):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("300x150")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Layer 1 Threshold:", font=("Segoe UI", 10, "bold"),
                 bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(pady=(20, 5))

        if not hasattr(self, 'threshold_var'):
            self.threshold_var = tk.DoubleVar(value=0.65)
        
        def on_threshold_change(val):
            if self.sniffer_service and hasattr(self.sniffer_service, 'engine'):
                self.sniffer_service.engine.l1_threshold = float(val)
                
        slider = tk.Scale(win, from_=0.01, to=0.99, resolution=0.01, 
                               orient=tk.HORIZONTAL, variable=self.threshold_var, 
                               command=on_threshold_change,
                               bg=COLORS['bg_card'], fg=COLORS['accent_cyan'],
                               activebackground=COLORS['accent_cyan'],
                               highlightthickness=0, bd=0, sliderrelief=tk.RAISED,
                               troughcolor=COLORS['border_light'])
        slider.pack(fill=tk.X, padx=20)

    def _create_nav_button(self, parent, icon, text, active=False):
        bg = COLORS['active_nav'] if active else COLORS['bg_sidebar']
        fg = COLORS['accent_cyan'] if active else COLORS['text_secondary']
        left_accent = COLORS['accent_cyan'] if active else COLORS['bg_sidebar']

        container = tk.Frame(parent, bg=COLORS['bg_sidebar'])
        container.pack(fill=tk.X)
        container.is_active = active

        # Left accent bar
        accent = tk.Frame(container, bg=left_accent, width=3)
        accent.pack(side=tk.LEFT, fill=tk.Y)

        btn = tk.Label(container, text=f"  {icon}  {text}", font=self.font_nav if not active else self.font_nav_bold,
                       bg=bg, fg=fg, anchor=tk.W, padx=12, pady=10, cursor="hand2")
        btn.pack(fill=tk.X, expand=True)

        # Hover effects
        def on_enter(e):
            if not getattr(container, 'is_active', False):
                btn.configure(bg=COLORS['hover'])
        def on_leave(e):
            if not getattr(container, 'is_active', False):
                btn.configure(bg=COLORS['bg_sidebar'])
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

        return container

    # ─────────────────────────────────────────────────────────
    #  HEADER
    # ─────────────────────────────────────────────────────────
    def _build_header(self, parent):
        header = tk.Frame(parent, bg=COLORS['bg_dark'], height=50)
        header.pack(fill=tk.X, padx=15, pady=(12, 0))
        header.pack_propagate(False)

        # Left: monitoring status
        left = tk.Frame(header, bg=COLORS['bg_dark'])
        left.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.lbl_monitor_dot = tk.Label(left, text="●", font=("Segoe UI", 10),
                                         bg=COLORS['bg_dark'], fg=COLORS['text_dim'])
        self.lbl_monitor_dot.pack(side=tk.LEFT, pady=12)
        self.lbl_monitor_text = tk.Label(left, text=" Idle", font=self.font_header,
                                          bg=COLORS['bg_dark'], fg=COLORS['text_dim'])
        self.lbl_monitor_text.pack(side=tk.LEFT, pady=12)

        # Right: clock + sniffer button
        right = tk.Frame(header, bg=COLORS['bg_dark'])
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        self.btn_sniffer = tk.Label(right, text="  ▶  Start Sniffing  ", font=self.font_btn,
                                     bg=COLORS['btn_start'], fg="white",
                                     padx=16, pady=6, cursor="hand2")
        self.btn_sniffer.pack(side=tk.RIGHT, pady=9)
        self.btn_sniffer.bind("<Button-1>", lambda e: self.toggle_sniffer())
        self.btn_sniffer.bind("<Enter>", lambda e: self.btn_sniffer.configure(
            bg='#1a7a3d' if not self.is_sniffing else '#b91c1c'))
        self.btn_sniffer.bind("<Leave>", lambda e: self.btn_sniffer.configure(
            bg=COLORS['btn_start'] if not self.is_sniffing else COLORS['btn_stop']))

        self.lbl_clock = tk.Label(right, text="00:00:00", font=self.font_clock,
                                   bg=COLORS['bg_dark'], fg=COLORS['text_secondary'])
        self.lbl_clock.pack(side=tk.RIGHT, padx=(0, 20), pady=12)
        tk.Label(right, text="🕐", font=("Segoe UI", 12),
                 bg=COLORS['bg_dark'], fg=COLORS['text_dim']).pack(side=tk.RIGHT, pady=12)

    # ─────────────────────────────────────────────────────────
    #  STAT CARDS
    # ─────────────────────────────────────────────────────────
    def _build_stat_cards(self, parent):
        row = tk.Frame(parent, bg=COLORS['bg_darkest'])
        row.pack(fill=tk.X, padx=15, pady=12)

        cards_config = [
            ("Total Alerts",      'total',  COLORS['accent_cyan']),
            ("High Severity",     'High',   COLORS['accent_red']),
            ("Medium Severity",   'Medium', COLORS['accent_amber']),
            ("Low Severity",      'Low',    COLORS['accent_green']),
            ("Packets Analyzed",  'pkts',   COLORS['accent_blue']),
        ]

        self.stat_labels = {}
        for title, key, color in cards_config:
            card = tk.Frame(row, bg=COLORS['bg_card'], highlightbackground=COLORS['border'],
                            highlightthickness=1, padx=18, pady=12)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

            # Top accent line
            accent = tk.Frame(card, bg=color, height=3)
            accent.pack(fill=tk.X, pady=(0, 10))

            tk.Label(card, text=title, font=self.font_stat_lbl,
                     bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(anchor=tk.W)

            num_lbl = tk.Label(card, text="0", font=self.font_stat_num,
                               bg=COLORS['bg_card'], fg=color)
            num_lbl.pack(anchor=tk.W, pady=(2, 0))
            self.stat_labels[key] = num_lbl

    # ─────────────────────────────────────────────────────────
    #  ALERTS TABLE
    # ─────────────────────────────────────────────────────────
    def _build_alerts_table(self, parent):
        # Section header
        section = tk.Frame(parent, bg=COLORS['bg_darkest'])
        section.pack(fill=tk.X, padx=15, pady=(0, 4))
        tk.Label(section, text="Recent Alerts", font=("Segoe UI", 13, "bold"),
                 bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)
        self.lbl_alert_count = tk.Label(section, text="0 alerts", font=self.font_stat_lbl,
                                         bg=COLORS['bg_darkest'], fg=COLORS['text_dim'])
        self.lbl_alert_count.pack(side=tk.RIGHT)

        # Table container
        table_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'],
                               highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 6))

        # Style the Treeview
        style = ttk.Style()
        style.theme_use("default")

        style.configure("Dark.Treeview",
                         background=COLORS['bg_card'],
                         foreground=COLORS['text_primary'],
                         fieldbackground=COLORS['bg_card'],
                         borderwidth=0,
                         font=self.font_table,
                         rowheight=32)
        style.configure("Dark.Treeview.Heading",
                         background=COLORS['bg_dark'],
                         foreground=COLORS['text_secondary'],
                         borderwidth=0,
                         font=self.font_table_header,
                         relief="flat")
        style.map("Dark.Treeview",
                   background=[("selected", COLORS['hover'])],
                   foreground=[("selected", COLORS['accent_cyan'])])
        style.map("Dark.Treeview.Heading",
                   background=[("active", COLORS['border'])])

        columns = ("time", "severity", "src_ip", "dst_ip", "attack", "confidence")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                  style="Dark.Treeview", selectmode="browse")

        self.tree.heading("time",       text="Time")
        self.tree.heading("severity",   text="Severity")
        self.tree.heading("src_ip",     text="Source IP")
        self.tree.heading("dst_ip",     text="Destination IP")
        self.tree.heading("attack",     text="Attack Type")
        self.tree.heading("confidence", text="Confidence")

        self.tree.column("time",       width=150, minwidth=120)
        self.tree.column("severity",   width=90,  minwidth=70, anchor=tk.CENTER)
        self.tree.column("src_ip",     width=140, minwidth=100)
        self.tree.column("dst_ip",     width=140, minwidth=100)
        self.tree.column("attack",     width=180, minwidth=120)
        self.tree.column("confidence", width=90,  minwidth=70, anchor=tk.CENTER)

        # Severity tag colors
        self.tree.tag_configure("High",   foreground=COLORS['accent_red'])
        self.tree.tag_configure("Medium", foreground=COLORS['accent_amber'])
        self.tree.tag_configure("Low",    foreground=COLORS['accent_green'])

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Empty state message
        self.lbl_empty = tk.Label(table_frame, text="No alerts yet — start the sniffer to begin monitoring",
                                   font=("Segoe UI", 11), bg=COLORS['bg_card'], fg=COLORS['text_dim'])
        self.lbl_empty.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    # ─────────────────────────────────────────────────────────
    #  CHART PANEL
    # ─────────────────────────────────────────────────────────
    def _build_chart(self, parent):
        section = tk.Frame(parent, bg=COLORS['bg_darkest'])
        section.pack(fill=tk.X, pady=(0, 4))
        tk.Label(section, text="Attack Distribution", font=("Segoe UI", 13, "bold"),
                 bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        chart_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'],
                               highlightthickness=1)
        chart_frame.pack(fill=tk.BOTH, expand=True)

        self.fig = Figure(figsize=(4.5, 3), facecolor=COLORS['bg_card'])
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(COLORS['bg_card'])
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self._update_chart()

    def _update_chart(self):
        self.ax.clear()
        
        if not self.alert_counts:
            self.ax.text(0.5, 0.5, "No Data", color=COLORS['text_dim'], 
                         ha='center', va='center', fontsize=12)
            self.ax.axis('off')
        else:
            labels = list(self.alert_counts.keys())
            sizes = list(self.alert_counts.values())
            
            palette = [
                COLORS['accent_blue'], COLORS['accent_amber'], COLORS['accent_red'], 
                COLORS['accent_cyan'], COLORS['accent_green'], '#a855f7', '#ec4899'
            ]
            
            ATTACK_COLORS = {
                'DoS': COLORS['accent_red'],
                'DDoS': '#991b1b',
                'Brute Force': COLORS['accent_amber'],
                'Port Scanning': COLORS['accent_blue'],
                'Bots': '#a855f7',
                'Web Attacks': '#ec4899',
            }
            
            colors = [ATTACK_COLORS.get(label, palette[i % len(palette)]) for i, label in enumerate(labels)]
                
            pie_result = self.ax.pie(
                sizes, colors=colors, autopct='%1.1f%%',
                startangle=90, textprops={'color': '#ffffff', 'fontsize': 9},
                radius=1.0
            )
            
            wedges = pie_result[0]
            autotexts = pie_result[2] if len(pie_result) >= 3 else []
            
            for autotext in autotexts:
                autotext.set_color('#ffffff')
                autotext.set_fontsize(9)
                
            self.ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1.05, 0.5),
                           ncol=1, frameon=False, labelcolor=COLORS['text_primary'], fontsize=10)
                
            self.ax.axis('equal')
            
        self.fig.subplots_adjust(left=0.05, right=0.55, top=0.95, bottom=0.05)
        self.canvas.draw()

    # ─────────────────────────────────────────────────────────
    #  LOG PANEL
    # ─────────────────────────────────────────────────────────
    def _build_log_panel(self, parent):
        log_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        log_frame.pack(fill=tk.X, padx=15, pady=(0, 10))

        # Header row
        log_header = tk.Frame(log_frame, bg=COLORS['bg_dark'])
        log_header.pack(fill=tk.X)
        tk.Label(log_header, text="  ⌨  Live Log", font=("Segoe UI", 10, "bold"),
                 bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, pady=5)

        # Log text
        self.log_text = tk.Text(log_frame, bg=COLORS['log_bg'], fg=COLORS['accent_green'],
                                 font=self.font_log, height=12, wrap=tk.WORD,
                                 borderwidth=0, highlightthickness=0,
                                 insertbackground=COLORS['accent_green'],
                                 selectbackground=COLORS['border_light'])
        self.log_text.pack(fill=tk.X)
        self.log_text.configure(state=tk.DISABLED)

        # Log tags
        self.log_text.tag_configure("info",    foreground=COLORS['accent_green'])
        self.log_text.tag_configure("alert",   foreground=COLORS['accent_red'], font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("warning", foreground=COLORS['accent_amber'])
        self.log_text.tag_configure("system",  foreground=COLORS['accent_cyan'])

        self._log("System initialized. Ready to sniff.\n", "system")

    # ══════════════════════════════════════════════════════════
    #  LOGIC
    # ══════════════════════════════════════════════════════════
    def _log(self, message, tag="info"):
        """Append a message to the log panel."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message, tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _tick_clock(self):
        """Update the clock label every second."""
        now = datetime.now().strftime("%H:%M:%S")
        self.lbl_clock.configure(text=now)
        self.root.after(1000, self._tick_clock)

    def _poll_packets(self):
        """Poll the sniffer's live packet count every 500ms."""
        if self.sniffer_service and self.is_sniffing:
            self.packets_analyzed = self.sniffer_service.packet_count
            self._update_stats()
            self.root.after(500, self._poll_packets)

    def _update_stats(self):
        """Refresh all stat card numbers."""
        self.stat_labels['total'].configure(text=str(self.stats['total']))
        self.stat_labels['High'].configure(text=str(self.stats['High']))
        self.stat_labels['Medium'].configure(text=str(self.stats['Medium']))
        self.stat_labels['Low'].configure(text=str(self.stats['Low']))
        self.stat_labels['pkts'].configure(text=str(self.packets_analyzed))
        self.lbl_alert_count.configure(text=f"{self.stats['total']} alerts")

    def _add_alert(self, src_ip, dst_ip, attack_type, confidence_str, details=None):
        """Add a row to the alerts table and update stats."""
        severity = SEVERITY_MAP.get(attack_type, "Medium")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Hide empty-state label
        self.lbl_empty.place_forget()
        
        alert_obj = {
            "id": f"A-{int(time.time() * 1000)}",
            "timestamp": timestamp,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": attack_type,
            "confidence": confidence_str,
            "details": details or {},
            "status": "active"
        }
        self.detailed_alerts.insert(0, alert_obj)
        if self.current_view == "Traffic Monitor":
            self._refresh_traffic_monitor()

        # Grouping Logic
        count = self.alert_counts.get(attack_type, 0) + 1
        self.alert_counts[attack_type] = count

        if count >= 16:
            group_iid = f"group_{attack_type}"
            if not self.tree.exists(group_iid):
                # Create parent folder row
                self.tree.insert("", 0, iid=group_iid, values=("Multiple", severity, "Various", "Various", f"{attack_type} Alerts", f"Total: {count}"), tags=(severity,))
                # Move all existing orphans of this type
                for item in self.tree.get_children(""):
                    if item != group_iid and self.tree.item(item, "values") and self.tree.item(item, "values")[4] == attack_type:
                        self.tree.move(item, group_iid, 0)
            else:
                # Update parent folder count and move it to top
                self.tree.item(group_iid, values=("Multiple", severity, "Various", "Various", f"{attack_type} Alerts", f"Total: {count}"))
                self.tree.move(group_iid, "", 0)
            
            # Insert new item inside the parent
            self.tree.insert(group_iid, 0, values=(timestamp, severity, src_ip, dst_ip, attack_type, confidence_str), tags=(severity,))
        else:
            # Insert at top of table
            self.tree.insert("", 0, values=(timestamp, severity, src_ip, dst_ip, attack_type, confidence_str),
                             tags=(severity,))

        # Update stats
        self.stats['total'] += 1
        self.stats[severity] = self.stats.get(severity, 0) + 1
        self._update_stats()
        self._update_chart()

        # Save to historical logs
        log_entry = {
            "timestamp": timestamp,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_type": attack_type,
            "confidence": confidence_str
        }
        self._save_historical_log(log_entry, details)

    def sniffer_log_callback(self, message, details=None):
        """
        Called by SnifferService on its background thread.
        We schedule UI updates on the main thread using root.after().
        """
        # Parse ALERT messages to extract structured data
        if "ALERT!" in message:
            # Format: "ALERT! [src] -> [dst] : Label (XX%)\n"
            try:
                parts = message.split("[")
                src_ip = parts[1].split("]")[0]
                dst_ip = parts[2].split("]")[0]
                rest = message.split(" : ")[1]
                attack_type = rest.split(" (")[0]
                confidence = rest.split("(")[1].rstrip(")\n")

                self.root.after(0, lambda s=src_ip, d=dst_ip, a=attack_type, c=confidence, det=details:
                                self._add_alert(s, d, a, c, det))
                self.root.after(0, lambda m=message: self._log(m, "alert"))
            except (IndexError, ValueError):
                self.root.after(0, lambda m=message: self._log(m, "warning"))
        else:
            tag = "system" if "Sniffer" in message or "Layer" in message else "info"
            self.root.after(0, lambda m=message, t=tag: self._log(m, t))



    def toggle_sniffer(self):
        if self.is_sniffing:
            # Stop
            self.sniffer_service.stop()
            self.is_sniffing = False
            self.btn_sniffer.configure(text="  ▶  Start Sniffing  ", bg=COLORS['btn_start'])
            self.lbl_sniffer_status.configure(text="● Stopped", fg=COLORS['accent_red'])
            self.lbl_monitor_dot.configure(fg=COLORS['text_dim'])
            self.lbl_monitor_text.configure(text=" Idle", fg=COLORS['text_dim'])
            self._log("Sniffer stopped.\n", "warning")
        else:
            # Start
            try:
                self.sniffer_service = SnifferService(INTERFACE_NAME, self.sniffer_log_callback)
                self.model_loaded = True
                self.lbl_model_status.configure(text="● Loaded", fg=COLORS['accent_green'])

                self.sniffer_thread = threading.Thread(target=self.sniffer_service.start)
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()

                self.is_sniffing = True
                self.btn_sniffer.configure(text="  ■  Stop Sniffing  ", bg=COLORS['btn_stop'])
                self.lbl_sniffer_status.configure(text="● Running", fg=COLORS['accent_green'])
                self.lbl_monitor_dot.configure(fg=COLORS['accent_green'])
                self.lbl_monitor_text.configure(text=" Monitoring", fg=COLORS['accent_green'])
                self._poll_packets()
            except Exception as e:
                self._log(f"Failed to start: {e}\n", "alert")
                self.lbl_model_status.configure(text="● Error", fg=COLORS['accent_red'])

    def _load_historical_logs(self):
        self.historical_logs = []
        try:
            alerts = session.query(Alert).join(TrafficLog).all()
            for a in alerts:
                self.historical_logs.append({
                    "id": str(a.AlertID),
                    "timestamp": a.Timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.Timestamp else "",
                    "severity": a.Severity,
                    "src_ip": a.associated_log.SourceIP,
                    "dst_ip": a.associated_log.DestIP,
                    "attack_type": a.AttackType,
                    "confidence": a.Confidence,
                    "details": {} # Optional details for UI
                })
        except Exception as e:
            print(f"Error loading historical logs from DB: {e}")

    def _save_historical_log(self, log_entry, details=None):
        try:
            # 1. Create Traffic Log
            protocol = details.get('protocol', 'TCP') if details else 'TCP'
            dst_port = details.get('dst_port', 0) if details else 0
            packet_size = details.get('packet_size', 0) if details else 0
            
            new_log = TrafficLog(
                SourceIP=log_entry.get('src_ip'),
                DestIP=log_entry.get('dst_ip'),
                Protocol=protocol,
                DstPort=dst_port,
                PacketSize=packet_size
            )
            session.add(new_log)
            session.flush() # to get LogID

            # 2. Create Alert
            new_alert = Alert(
                AssociatedLogID=new_log.LogID,
                AttackType=log_entry.get('attack_type'),
                Severity=log_entry.get('severity'),
                Confidence=log_entry.get('confidence'),
                Status="active"
            )
            session.add(new_alert)
            session.commit()
            
            log_entry["id"] = str(new_alert.AlertID)
            self.historical_logs.append(log_entry)
        except Exception as e:
            print(f"Error saving historical log to DB: {e}")
            session.rollback()

    def _switch_view(self, view_name):
        if view_name == self.current_view:
            return
            
        for container, label in self.nav_buttons:
            is_active = (label == view_name)
            container.is_active = is_active
            
            bg = COLORS['active_nav'] if is_active else COLORS['bg_sidebar']
            fg = COLORS['accent_cyan'] if is_active else COLORS['text_secondary']
            left_accent = COLORS['accent_cyan'] if is_active else COLORS['bg_sidebar']
            font = self.font_nav_bold if is_active else self.font_nav
            
            children = container.winfo_children()
            if len(children) >= 2:
                accent = children[0]
                btn_lbl = children[1]
                accent.configure(bg=left_accent)
                btn_lbl.configure(bg=bg, fg=fg, font=font)
        
        if view_name == "Dashboard":
            self.frame_historical.pack_forget()
            if hasattr(self, 'frame_traffic_monitor'): self.frame_traffic_monitor.pack_forget()
            if hasattr(self, 'frame_rules'): self.frame_rules.pack_forget()
            self.frame_dashboard.pack(fill=tk.BOTH, expand=True)
            self.current_view = "Dashboard"
        elif view_name == "Historical Logs":
            self.frame_dashboard.pack_forget()
            if hasattr(self, 'frame_traffic_monitor'): self.frame_traffic_monitor.pack_forget()
            if hasattr(self, 'frame_rules'): self.frame_rules.pack_forget()
            self.frame_historical.pack(fill=tk.BOTH, expand=True)
            self.current_view = "Historical Logs"
            self._refresh_historical_table()
        elif view_name == "Traffic Monitor":
            self.frame_dashboard.pack_forget()
            self.frame_historical.pack_forget()
            if hasattr(self, 'frame_rules'): self.frame_rules.pack_forget()
            self.frame_traffic_monitor.pack(fill=tk.BOTH, expand=True)
            self.current_view = "Traffic Monitor"
            self._refresh_traffic_monitor()
        elif view_name == "Rules":
            self.frame_dashboard.pack_forget()
            if hasattr(self, 'frame_historical'): self.frame_historical.pack_forget()
            if hasattr(self, 'frame_traffic_monitor'): self.frame_traffic_monitor.pack_forget()
            self.frame_rules.pack(fill=tk.BOTH, expand=True)
            self.current_view = "Rules"
            self._refresh_rules_table()

    def _build_historical_ui(self, parent):
        # Header
        header = tk.Frame(parent, bg=COLORS['bg_dark'], height=50)
        header.pack(fill=tk.X, padx=15, pady=(12, 0))
        header.pack_propagate(False)
        tk.Label(header, text="Historical Logs", font=self.font_header, bg=COLORS['bg_dark'], fg=COLORS['text_primary']).pack(side=tk.LEFT, padx=15, pady=12)

        # Search Bar Area
        search_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        search_frame.pack(fill=tk.X, padx=15, pady=(15, 0))
        
        tk.Label(search_frame, text="Search IP:", font=self.font_table, bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, padx=(15, 5), pady=15)
        self.ent_search_ip = tk.Entry(search_frame, font=self.font_table, bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT, width=20)
        self.ent_search_ip.pack(side=tk.LEFT, ipady=4)
        
        tk.Label(search_frame, text="Attack Type:", font=self.font_table, bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, padx=(20, 5), pady=15)
        self.cb_search_attack = ttk.Combobox(search_frame, values=["All"] + list(SEVERITY_MAP.keys()), state="readonly", font=self.font_table, width=15)
        self.cb_search_attack.set("All")
        self.cb_search_attack.pack(side=tk.LEFT, ipady=2)
        
        btn_search = tk.Button(search_frame, text="Search", font=self.font_btn, bg=COLORS['accent_blue'], fg="white", relief=tk.FLAT, cursor="hand2", command=self._do_historical_search)
        btn_search.pack(side=tk.LEFT, padx=(20, 15), ipady=2, ipadx=10)

        # Table container
        table_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        columns = ("time", "severity", "src_ip", "dst_ip", "attack", "confidence")
        self.hist_tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Dark.Treeview", selectmode="browse")

        self.hist_tree.heading("time",       text="Time")
        self.hist_tree.heading("severity",   text="Severity")
        self.hist_tree.heading("src_ip",     text="Source IP")
        self.hist_tree.heading("dst_ip",     text="Destination IP")
        self.hist_tree.heading("attack",     text="Attack Type")
        self.hist_tree.heading("confidence", text="Confidence")

        self.hist_tree.column("time",       width=150, minwidth=120)
        self.hist_tree.column("severity",   width=90,  minwidth=70, anchor=tk.CENTER)
        self.hist_tree.column("src_ip",     width=140, minwidth=100)
        self.hist_tree.column("dst_ip",     width=140, minwidth=100)
        self.hist_tree.column("attack",     width=180, minwidth=120)
        self.hist_tree.column("confidence", width=90,  minwidth=70, anchor=tk.CENTER)

        self.hist_tree.tag_configure("High",   foreground=COLORS['accent_red'])
        self.hist_tree.tag_configure("Medium", foreground=COLORS['accent_amber'])
        self.hist_tree.tag_configure("Low",    foreground=COLORS['accent_green'])

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=scrollbar.set)

        self.hist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Action Area
        action_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        action_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.btn_scan = tk.Button(action_frame, text="🔍 In-Depth IP Scan", font=self.font_btn, bg=COLORS['accent_cyan'], fg="black", relief=tk.FLAT, cursor="hand2", command=self._do_indepth_scan)
        self.btn_scan.pack(side=tk.RIGHT, ipady=4, ipadx=10)

    def _refresh_historical_table(self, logs=None):
        if logs is None:
            logs = self.historical_logs
            
        for item in self.hist_tree.get_children():
            self.hist_tree.delete(item)
            
        for log in reversed(logs):
            self.hist_tree.insert("", tk.END, values=(
                log.get('timestamp', ''),
                log.get('severity', ''),
                log.get('src_ip', ''),
                log.get('dst_ip', ''),
                log.get('attack_type', ''),
                log.get('confidence', '')
            ), tags=(log.get('severity', ''),))

    def _do_historical_search(self):
        query_ip = self.ent_search_ip.get().strip()
        query_attack = self.cb_search_attack.get()
        
        results = []
        for log in self.historical_logs:
            match_ip = (query_ip == "" or query_ip in log.get('src_ip', '') or query_ip in log.get('dst_ip', ''))
            match_attack = (query_attack == "All" or query_attack == log.get('attack_type', ''))
            
            if match_ip and match_attack:
                results.append(log)
                
        self._refresh_historical_table(results)

    def _do_indepth_scan(self):
        selected = self.hist_tree.selection()
        if not selected:
            return
            
        item = self.hist_tree.item(selected[0])
        src_ip_full = str(item['values'][2])
        src_ip = src_ip_full.split(':')[0]
        
        ip_logs = []
        for log in self.historical_logs:
            log_src = str(log.get('src_ip', '')).split(':')[0]
            if log_src == src_ip:
                ip_logs.append(log)
                
        if not ip_logs:
            return
            
        total = len(ip_logs)
        types = {}
        for log in ip_logs:
            t = log.get('attack_type', 'Unknown')
            types[t] = types.get(t, 0) + 1
            
        first_seen = ip_logs[0].get('timestamp', 'N/A') if ip_logs else 'N/A'
        last_seen = ip_logs[-1].get('timestamp', 'N/A') if ip_logs else 'N/A'
        
        win = tk.Toplevel(self.root)
        win.title(f"In-Depth Scan: {src_ip}")
        win.geometry("400x300")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.root)
        win.grab_set()
        
        tk.Label(win, text=f"Analysis for {src_ip}", font=("Segoe UI", 14, "bold"), bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(pady=(20, 10))
        
        stats_frame = tk.Frame(win, bg=COLORS['bg_dark'], padx=20, pady=20)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        tk.Label(stats_frame, text=f"Total Attacks: {total}", font=self.font_table_header, bg=COLORS['bg_dark'], fg=COLORS['accent_cyan']).pack(anchor=tk.W, pady=2)
        tk.Label(stats_frame, text=f"First Seen: {first_seen}", font=self.font_table, bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=2)
        tk.Label(stats_frame, text=f"Last Seen: {last_seen}", font=self.font_table, bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=2)
        
        tk.Label(stats_frame, text="Attack Types Profile:", font=self.font_table_header, bg=COLORS['bg_dark'], fg=COLORS['text_primary']).pack(anchor=tk.W, pady=(10, 2))
        for t, c in types.items():
            tk.Label(stats_frame, text=f"  • {t}: {c}", font=self.font_table, bg=COLORS['bg_dark'], fg=COLORS['accent_amber']).pack(anchor=tk.W)

    # ─────────────────────────────────────────────────────────
    #  TRAFFIC MONITOR UI & LOGIC
    # ─────────────────────────────────────────────────────────
    def _build_traffic_monitor_ui(self, parent):
        header = tk.Frame(parent, bg=COLORS['bg_darkest'])
        header.pack(fill=tk.X, padx=30, pady=(25, 10))
        tk.Label(header, text="Traffic Monitor (Incident Response)", font=("Segoe UI", 24, "bold"),
                 bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        paned = tk.PanedWindow(parent, orient=tk.HORIZONTAL, bg=COLORS['border_light'], sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)

        left_frame = tk.Frame(paned, bg=COLORS['bg_card'])
        paned.add(left_frame, minsize=300)
        
        tk.Label(left_frame, text="Active Unresolved Alerts", font=("Segoe UI", 12, "bold"),
                 bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=15, pady=15)
                 
        self.tm_listbox = tk.Listbox(left_frame, bg=COLORS['log_bg'], fg=COLORS['text_primary'],
                                     selectbackground=COLORS['active_nav'], selectforeground=COLORS['accent_cyan'],
                                     font=("Consolas", 10), borderwidth=0, highlightthickness=0)
        self.tm_listbox.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        self.tm_listbox.bind('<<ListboxSelect>>', self._on_tm_alert_select)
        
        self.tm_right_frame = tk.Frame(paned, bg=COLORS['bg_card'])
        paned.add(self.tm_right_frame, minsize=400)
        
        self.tm_lbl_title = tk.Label(self.tm_right_frame, text="Select an alert to view details", font=("Segoe UI", 16, "bold"),
                                     bg=COLORS['bg_card'], fg=COLORS['text_primary'])
        self.tm_lbl_title.pack(anchor=tk.W, padx=20, pady=(20, 10))
        
        self.tm_lbl_info = tk.Label(self.tm_right_frame, text="", font=("Segoe UI", 11), justify=tk.LEFT,
                                    bg=COLORS['bg_card'], fg=COLORS['text_secondary'])
        self.tm_lbl_info.pack(anchor=tk.W, padx=20, pady=5)
        
        self.tm_lbl_mechanism = tk.Label(self.tm_right_frame, text="", font=("Segoe UI", 11, "italic"), justify=tk.LEFT,
                                         bg=COLORS['bg_card'], fg=COLORS['accent_amber'])
        self.tm_lbl_mechanism.pack(anchor=tk.W, padx=20, pady=(0, 20))
        
        payload_controls = tk.Frame(self.tm_right_frame, bg=COLORS['bg_card'])
        payload_controls.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(payload_controls, text="Payload Samples:", font=("Segoe UI", 11, "bold"),
                 bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(side=tk.LEFT)
                 
        self.tm_payload_mode = tk.StringVar(value="text")
        tk.Radiobutton(payload_controls, text="Text", variable=self.tm_payload_mode, value="text", 
                       bg=COLORS['bg_card'], fg=COLORS['text_primary'], selectcolor=COLORS['bg_dark'],
                       activebackground=COLORS['bg_card'], activeforeground=COLORS['accent_cyan'],
                       command=self._update_payload_view).pack(side=tk.RIGHT)
        tk.Radiobutton(payload_controls, text="Hex", variable=self.tm_payload_mode, value="hex", 
                       bg=COLORS['bg_card'], fg=COLORS['text_primary'], selectcolor=COLORS['bg_dark'],
                       activebackground=COLORS['bg_card'], activeforeground=COLORS['accent_cyan'],
                       command=self._update_payload_view).pack(side=tk.RIGHT, padx=10)

        self.tm_text_payload = tk.Text(self.tm_right_frame, bg=COLORS['log_bg'], fg=COLORS['text_primary'],
                                       font=("Consolas", 10), borderwidth=0, highlightthickness=1, highlightbackground=COLORS['border'])
        self.tm_text_payload.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.tm_text_payload.config(state=tk.DISABLED)

        actions_frame = tk.Frame(self.tm_right_frame, bg=COLORS['bg_card'])
        actions_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.btn_ack = tk.Button(actions_frame, text="✅ Acknowledge", font=self.font_btn, bg=COLORS['bg_dark'], fg="white", 
                                 relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("ack"))
        self.btn_ack.pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
        
        self.btn_fp = tk.Button(actions_frame, text="❌ False Positive", font=self.font_btn, bg=COLORS['bg_dark'], fg="white", 
                                relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("fp"))
        self.btn_fp.pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)

        self.btn_block = tk.Button(actions_frame, text="🚫 Block Source IP", font=self.font_btn, bg=COLORS['btn_stop'], fg="white", 
                                   relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("block"))
        self.btn_block.pack(side=tk.RIGHT, ipady=4, ipadx=10)
        
        self._toggle_tm_actions(False)

    def _refresh_traffic_monitor(self):
        self.tm_listbox.delete(0, tk.END)
        self.tm_active_indices = []
        for i, alt in enumerate(self.detailed_alerts):
            if alt["status"] == "active":
                self.tm_listbox.insert(tk.END, f"[{alt['severity']}] {alt['src_ip']} - {alt['attack_type']}")
                self.tm_active_indices.append(i)
                
    def _on_tm_alert_select(self, event):
        sel = self.tm_listbox.curselection()
        if not sel:
            self._toggle_tm_actions(False)
            return
        idx = self.tm_active_indices[sel[0]]
        alt = self.detailed_alerts[idx]
        self.tm_selected_index = idx
        
        self.tm_lbl_title.config(text=f"Alert {alt['id']} Details")
        self.tm_lbl_info.config(text=f"Time: {alt['timestamp']}\nSource: {alt['src_ip']}\nDestination: {alt['dst_ip']}\nType: {alt['attack_type']}\nConfidence: {alt['confidence']}")
        mech = alt.get("details", {}).get("rule_triggered", "Unknown Mechanism")
        self.tm_lbl_mechanism.config(text=f"Detection Mechanism: {mech}")
        
        self._toggle_tm_actions(True)
        self._update_payload_view()
        
    def _update_payload_view(self):
        if not hasattr(self, 'tm_selected_index') or self.tm_selected_index is None:
            return
        alt = self.detailed_alerts[self.tm_selected_index]
        payloads = alt.get("details", {}).get("payloads", [])
        
        mode = self.tm_payload_mode.get()
        content = ""
        if not payloads:
            content = "No payload captured for this flow."
        else:
            for i, p in enumerate(payloads):
                content += f"--- Packet {i+1} ---\n"
                if mode == "text":
                    text_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in p)
                    content += text_str + "\n\n"
                else:
                    hex_bytes = [f"{b:02x}" for b in p]
                    lines = [" ".join(hex_bytes[j:j+16]) for j in range(0, len(hex_bytes), 16)]
                    content += "\n".join(lines) + "\n\n"
                    
        self.tm_text_payload.config(state=tk.NORMAL)
        self.tm_text_payload.delete(1.0, tk.END)
        self.tm_text_payload.insert(tk.END, content)
        self.tm_text_payload.config(state=tk.DISABLED)

    def _handle_alert_action(self, action):
        if not hasattr(self, 'tm_selected_index') or self.tm_selected_index is None:
            return
        alt = self.detailed_alerts[self.tm_selected_index]
        if action == "ack":
            alt["status"] = "acknowledged"
            self._log(f"Alert {alt['id']} marked as acknowledged.", "success")
        elif action == "fp":
            alt["status"] = "false_positive"
            self._log(f"Alert {alt['id']} marked as false positive.", "warning")
        elif action == "block":
            alt["status"] = "blocked"
            self._log(f"Source IP {alt['src_ip']} blocked.", "alert")
            
        self.tm_selected_index = None
        self.tm_lbl_title.config(text="Select an alert to view details")
        self.tm_lbl_info.config(text="")
        self.tm_lbl_mechanism.config(text="")
        self.tm_text_payload.config(state=tk.NORMAL)
        self.tm_text_payload.delete(1.0, tk.END)
        self.tm_text_payload.config(state=tk.DISABLED)
        self._toggle_tm_actions(False)
        self._refresh_traffic_monitor()
        
    def _toggle_tm_actions(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.btn_ack.config(state=state)
        self.btn_fp.config(state=state)
        self.btn_block.config(state=state)

    # ─────────────────────────────────────────────────────────
    #  RULES UI & LOGIC
    # ─────────────────────────────────────────────────────────
    def _load_rules(self):
        self.rules = []
        try:
            db_rules = session.query(Rule).all()
            for r in db_rules:
                self.rules.append({
                    "id": r.RuleID,
                    "name": r.RuleName,
                    "description": r.Description,
                    "action": r.Severity,
                    "status": "active" if r.IsActive else "paused",
                    "logic": {
                        "field": r.ConditionText.split(' ', 1)[0] if r.ConditionText else "",
                        "condition": "",
                        "value": r.ConditionText.split(' ', 1)[1] if r.ConditionText and ' ' in r.ConditionText else ""
                    }
                })
        except Exception as e:
            print(f"Error loading rules from DB: {e}")
            self.rules = []
            
    def _save_rules(self):
        try:
            for r in self.rules:
                rule_id = r.get("id")
                condition_text = f"{r.get('logic', {}).get('field', '')} {r.get('logic', {}).get('value', '')}"
                is_active = r.get("status") == "active"
                
                if isinstance(rule_id, int): # Existing rule
                    db_rule = session.get(Rule, rule_id)
                    if db_rule:
                        db_rule.RuleName = r.get("name")
                        db_rule.Description = r.get("description")
                        db_rule.Severity = r.get("action")
                        db_rule.ConditionText = condition_text
                        db_rule.IsActive = is_active
                else: # New rule
                    new_rule = Rule(
                        RuleName=r.get("name"),
                        Description=r.get("description"),
                        Severity=r.get("action"),
                        ConditionText=condition_text,
                        IsActive=is_active,
                        CreatedBy=self.current_user.UserID if hasattr(self, 'current_user') else None
                    )
                    session.add(new_rule)
                    session.flush()
                    r["id"] = new_rule.RuleID # Update ID from DB
                    
            session.commit()
            if self.sniffer_service and hasattr(self.sniffer_service, 'heuristic_engine'):
                self.sniffer_service.heuristic_engine.reload_rules()
        except Exception as e:
            print(f"Error saving rules: {str(e)}")
            session.rollback()

    def _build_rules_ui(self, parent):
        header = tk.Frame(parent, bg=COLORS['bg_darkest'])
        header.pack(fill=tk.X, padx=30, pady=(25, 10))
        tk.Label(header, text="Rule Management", font=("Segoe UI", 24, "bold"),
                 bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        self.rules_control_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        self.rules_control_frame.pack(fill=tk.X, padx=30, pady=(0, 10))
        
        tk.Button(self.rules_control_frame, text="➕ Add New Rule", font=self.font_btn, bg=COLORS['accent_blue'], fg="white", 
                  relief=tk.FLAT, cursor="hand2", command=lambda: self._show_rule_form()).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
        
        tk.Button(self.rules_control_frame, text="✏️ Edit", font=self.font_btn, bg=COLORS['bg_card'], fg=COLORS['text_primary'], 
                  relief=tk.FLAT, cursor="hand2", command=self._edit_selected_rule).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
                  
        tk.Button(self.rules_control_frame, text="⏸ Pause / Resume", font=self.font_btn, bg=COLORS['bg_card'], fg=COLORS['text_primary'], 
                  relief=tk.FLAT, cursor="hand2", command=self._toggle_rule_status).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
                  
        tk.Button(self.rules_control_frame, text="🗑️ Delete", font=self.font_btn, bg=COLORS['btn_stop'], fg="white", 
                  relief=tk.FLAT, cursor="hand2", command=self._delete_selected_rule).pack(side=tk.RIGHT, ipady=4, ipadx=10)

        table_frame = tk.Frame(parent, bg=COLORS['bg_card'])
        table_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))

        scroll_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        cols = ("ID", "Name", "Action", "Status", "Target Field", "Condition")
        self.rules_tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                       yscrollcommand=scroll_y.set, selectmode="browse")
        
        col_widths = [80, 250, 100, 80, 120, 150]
        for c, w in zip(cols, col_widths):
            self.rules_tree.heading(c, text=c)
            self.rules_tree.column(c, width=w, anchor=tk.W)

        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.config(command=self.rules_tree.yview)
        
    def _refresh_rules_table(self):
        if not hasattr(self, 'rules_tree'): return
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        for rule in self.rules:
            logic = rule.get("logic", {})
            field = logic.get("field", "")
            condition = f"{logic.get('condition', '')} {logic.get('value', '')}"
            self.rules_tree.insert("", tk.END, values=(
                rule.get("id", ""),
                rule.get("name", ""),
                rule.get("action", ""),
                rule.get("status", ""),
                field,
                condition
            ))

    def _show_rule_form(self, rule_idx=None):
        win = tk.Toplevel(self.root)
        win.title("Rule Configuration")
        win.geometry("500x550")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.root)
        win.grab_set()

        rule = self.rules[rule_idx] if rule_idx is not None else {}

        tk.Label(win, text="Rule Name:", font=self.font_table_header, bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(20, 5))
        var_name = tk.StringVar(value=rule.get("name", ""))
        tk.Entry(win, textvariable=var_name, font=self.font_table, bg=COLORS['bg_dark'], fg="white", insertbackground="white").pack(fill=tk.X, padx=20)

        tk.Label(win, text="Description:", font=self.font_table_header, bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(15, 5))
        text_desc = tk.Text(win, height=3, font=self.font_table, bg=COLORS['bg_dark'], fg="white", insertbackground="white")
        text_desc.pack(fill=tk.X, padx=20)
        text_desc.insert(1.0, rule.get("description", ""))

        logic_frame = tk.LabelFrame(win, text="Detection Logic", font=self.font_table_header, bg=COLORS['bg_card'], fg=COLORS['accent_cyan'], padx=10, pady=10)
        logic_frame.pack(fill=tk.X, padx=20, pady=15)
        
        logic = rule.get("logic", {})
        
        tk.Label(logic_frame, text="Target Field:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=0, column=0, sticky=tk.W, pady=5)
        var_field = tk.StringVar(value=logic.get("field", "Source IP"))
        ttk.Combobox(logic_frame, textvariable=var_field, values=["Source IP", "Dest IP", "Port", "Protocol", "Packet Count"], state="readonly").grid(row=0, column=1, sticky=tk.EW, padx=10)

        tk.Label(logic_frame, text="Condition:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=1, column=0, sticky=tk.W, pady=5)
        var_cond = tk.StringVar(value=logic.get("condition", "Equals"))
        ttk.Combobox(logic_frame, textvariable=var_cond, values=["Equals", "Contains", "Greater Than", "Less Than"], state="readonly").grid(row=1, column=1, sticky=tk.EW, padx=10)

        tk.Label(logic_frame, text="Value:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=2, column=0, sticky=tk.W, pady=5)
        var_val = tk.StringVar(value=logic.get("value", ""))
        tk.Entry(logic_frame, textvariable=var_val, bg=COLORS['bg_dark'], fg="white", insertbackground="white").grid(row=2, column=1, sticky=tk.EW, padx=10)
        
        logic_frame.columnconfigure(1, weight=1)

        tk.Label(win, text="Action:", font=self.font_table_header, bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(5, 5))
        var_action = tk.StringVar(value=rule.get("action", "Alert High"))
        ttk.Combobox(win, textvariable=var_action, values=["Alert High", "Alert Medium", "Alert Low", "Drop / Block"], state="readonly").pack(fill=tk.X, padx=20)

        tk.Label(win, text="Initial Status:", font=self.font_table_header, bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(15, 5))
        var_status = tk.StringVar(value=rule.get("status", "active"))
        ttk.Combobox(win, textvariable=var_status, values=["active", "paused"], state="readonly").pack(fill=tk.X, padx=20)

        def _save():
            new_rule = {
                "id": rule.get("id", f"R-{int(time.time() * 1000)}"),
                "name": var_name.get().strip() or "Unnamed Rule",
                "description": text_desc.get(1.0, tk.END).strip(),
                "action": var_action.get(),
                "status": var_status.get(),
                "logic": {
                    "field": var_field.get(),
                    "condition": var_cond.get(),
                    "value": var_val.get().strip()
                }
            }
            if rule_idx is not None:
                self.rules[rule_idx] = new_rule
            else:
                self.rules.append(new_rule)
                
            self._save_rules()
            self._refresh_rules_table()
            win.destroy()

        tk.Button(win, text="💾 Save Rule", font=self.font_btn, bg=COLORS['accent_green'], fg="black", 
                  relief=tk.FLAT, cursor="hand2", command=_save).pack(pady=(30, 20), ipady=5, ipadx=20)
                  
    def _edit_selected_rule(self):
        sel = self.rules_tree.selection()
        if not sel: return
        item = self.rules_tree.item(sel[0])
        rule_id = item['values'][0]
        for i, r in enumerate(self.rules):
            if r.get("id") == rule_id:
                self._show_rule_form(i)
                break
                
    def _toggle_rule_status(self):
        sel = self.rules_tree.selection()
        if not sel: return
        item = self.rules_tree.item(sel[0])
        rule_id = item['values'][0]
        for r in self.rules:
            if r.get("id") == rule_id:
                r["status"] = "paused" if r.get("status") == "active" else "active"
                break
        self._save_rules()
        self._refresh_rules_table()
        
    def _delete_selected_rule(self):
        sel = self.rules_tree.selection()
        if not sel: return
        item = self.rules_tree.item(sel[0])
        rule_id = item['values'][0]
        
        try:
            if isinstance(rule_id, int):
                db_rule = session.get(Rule, rule_id)
                if db_rule:
                    session.delete(db_rule)
                    session.commit()
                    if self.sniffer_service and hasattr(self.sniffer_service, 'heuristic_engine'):
                        self.sniffer_service.heuristic_engine.reload_rules()
        except Exception:
            session.rollback()
            
        self.rules = [r for r in self.rules if r.get("id") != rule_id]
        self._refresh_rules_table()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IDSDashboard(root)
        root.mainloop()
    except KeyboardInterrupt:
        pass