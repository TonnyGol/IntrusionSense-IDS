import sys
import os

# --- Path Fix (must be first!) ---
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import tkinter as tk
from tkinter import ttk, font as tkfont
import threading
import time
from datetime import datetime
from sniffer_service import SnifferService
from net_utils import get_active_interface_name

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

        self._build_ui()
        self._tick_clock()

    # ══════════════════════════════════════════════════════════
    #  BUILD UI
    # ══════════════════════════════════════════════════════════
    def _build_ui(self):
        # ── Sidebar ──────────────────────────────────────────
        self.sidebar = tk.Frame(self.root, bg=COLORS['bg_sidebar'], width=240)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        self._build_sidebar()

        # ── Main Area ────────────────────────────────────────
        main = tk.Frame(self.root, bg=COLORS['bg_darkest'])
        main.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._build_header(main)
        self._build_stat_cards(main)
        self._build_alerts_table(main)
        self._build_log_panel(main)

    # ─────────────────────────────────────────────────────────
    #  SIDEBAR
    # ─────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = self.sidebar

        # Brand
        brand_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'])
        brand_frame.pack(pady=(20, 30))
        tk.Label(brand_frame, text="🛡️", font=("Segoe UI", 20),
                 bg=COLORS['bg_sidebar'], fg=COLORS['accent_cyan']).pack(side=tk.LEFT)
        tk.Label(brand_frame, text=" IntrusionSense", font=("Segoe UI", 14, "bold"),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        # Navigation
        nav_items = [
            ("📊", "Dashboard", True),
            ("🔔", "Alerts", False),
            ("📡", "Traffic Monitor", False),
            ("📋", "Historical Logs", False),
            ("⚙️", "Settings", False),
        ]
        self.nav_buttons = []
        for icon, label, active in nav_items:
            btn = self._create_nav_button(sb, icon, label, active)
            self.nav_buttons.append((btn, label))

        # Spacer
        tk.Frame(sb, bg=COLORS['bg_sidebar']).pack(fill=tk.BOTH, expand=True)

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

    def _create_nav_button(self, parent, icon, text, active=False):
        bg = COLORS['active_nav'] if active else COLORS['bg_sidebar']
        fg = COLORS['accent_cyan'] if active else COLORS['text_secondary']
        left_accent = COLORS['accent_cyan'] if active else COLORS['bg_sidebar']

        container = tk.Frame(parent, bg=COLORS['bg_sidebar'])
        container.pack(fill=tk.X)

        # Left accent bar
        accent = tk.Frame(container, bg=left_accent, width=3)
        accent.pack(side=tk.LEFT, fill=tk.Y)

        btn = tk.Label(container, text=f"  {icon}  {text}", font=self.font_nav if not active else self.font_nav_bold,
                       bg=bg, fg=fg, anchor=tk.W, padx=12, pady=10, cursor="hand2")
        btn.pack(fill=tk.X, expand=True)

        # Hover effects
        def on_enter(e):
            if not active:
                btn.configure(bg=COLORS['hover'])
        def on_leave(e):
            if not active:
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
                                 font=self.font_log, height=6, wrap=tk.WORD,
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

    def _add_alert(self, src_ip, dst_ip, attack_type, confidence_str):
        """Add a row to the alerts table and update stats."""
        severity = SEVERITY_MAP.get(attack_type, "Medium")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Hide empty-state label
        self.lbl_empty.place_forget()

        # Insert at top of table
        self.tree.insert("", 0, values=(timestamp, severity, src_ip, dst_ip, attack_type, confidence_str),
                         tags=(severity,))

        # Update stats
        self.stats['total'] += 1
        self.stats[severity] = self.stats.get(severity, 0) + 1
        self._update_stats()

    def sniffer_log_callback(self, message):
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

                self.root.after(0, lambda s=src_ip, d=dst_ip, a=attack_type, c=confidence:
                                self._add_alert(s, d, a, c))
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


if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IDSDashboard(root)
        root.mainloop()
    except KeyboardInterrupt:
        pass