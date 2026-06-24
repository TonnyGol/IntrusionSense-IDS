import tkinter as tk
from .style_constants import COLORS, get_fonts

class Sidebar:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_sidebar()

    def _build_sidebar(self):
        sb = self.frame

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
        self.dashboard.nav_buttons = []
        for icon, label, active in nav_items:
            btn = self._create_nav_button(sb, icon, label, active)
            if label == "Settings":
                btn.bind("<Button-1>", self.dashboard._open_settings)
                for child in btn.winfo_children():
                    child.bind("<Button-1>", self.dashboard._open_settings)
            elif label in ["Dashboard", "Historical Logs", "Traffic Monitor", "Rules"]:
                btn.bind("<Button-1>", lambda e, l=label: self.dashboard._switch_view(l))
                for child in btn.winfo_children():
                    child.bind("<Button-1>", lambda e, l=label: self.dashboard._switch_view(l))
            self.dashboard.nav_buttons.append((btn, label))

        # Spacer
        tk.Frame(sb, bg=COLORS['bg_sidebar']).pack(fill=tk.BOTH, expand=True)

        # Logout Button
        logout_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'])
        logout_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        tk.Button(logout_frame, text="🚪 Logout", font=self.fonts['btn'], bg=COLORS['border'], fg=COLORS['text_primary'],
                  relief=tk.FLAT, cursor="hand2", command=self.dashboard.login_view.do_logout).pack(fill=tk.X, ipady=4)

        # ── System Status ────────────────────────────────────
        status_frame = tk.Frame(sb, bg=COLORS['bg_sidebar'])
        status_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        tk.Label(status_frame, text="System Status", font=("Segoe UI", 10, "bold"),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=(0, 8))

        # Sniffer status
        row_sniff = tk.Frame(status_frame, bg=COLORS['bg_sidebar'])
        row_sniff.pack(fill=tk.X, pady=2)
        tk.Label(row_sniff, text="Sniffer:", font=self.fonts['status'],
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(side=tk.LEFT)
        self.dashboard.lbl_sniffer_status = tk.Label(row_sniff, text="● Stopped", font=self.fonts['status'],
                                           bg=COLORS['bg_sidebar'], fg=COLORS['accent_red'])
        self.dashboard.lbl_sniffer_status.pack(side=tk.RIGHT)

        # Model status
        row_model = tk.Frame(status_frame, bg=COLORS['bg_sidebar'])
        row_model.pack(fill=tk.X, pady=2)
        tk.Label(row_model, text="ML Model:", font=self.fonts['status'],
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(side=tk.LEFT)
        self.dashboard.lbl_model_status = tk.Label(row_model, text="● Not Loaded", font=self.fonts['status'],
                                         bg=COLORS['bg_sidebar'], fg=COLORS['text_dim'])
        self.dashboard.lbl_model_status.pack(side=tk.RIGHT)

        # Version
        tk.Label(status_frame, text="Version 1.0.0", font=("Segoe UI", 8),
                 bg=COLORS['bg_sidebar'], fg=COLORS['text_dim']).pack(anchor=tk.W, pady=(10, 0))

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

        btn = tk.Label(container, text=f"  {icon}  {text}", font=self.fonts['nav'] if not active else self.fonts['nav_bold'],
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
