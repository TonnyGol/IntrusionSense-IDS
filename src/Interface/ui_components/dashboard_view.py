import tkinter as tk
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from .style_constants import COLORS, get_fonts

class DashboardView:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_dashboard_ui()

    def _build_dashboard_ui(self):
        self._build_header(self.frame)
        self._build_stat_cards(self.frame)

        middle = tk.Frame(self.frame, bg=COLORS['bg_darkest'])
        middle.pack(fill=tk.BOTH, expand=True)

        table_area = tk.Frame(middle, bg=COLORS['bg_darkest'])
        table_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        chart_area = tk.Frame(middle, bg=COLORS['bg_darkest'])
        chart_area.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(0, 15), pady=(0, 6))

        self._build_alerts_table(table_area)
        self._build_chart(chart_area)
        self._build_log_panel(self.frame)

    def _build_header(self, parent):
        header = tk.Frame(parent, bg=COLORS['bg_dark'], height=50)
        header.pack(fill=tk.X, padx=15, pady=(12, 0))
        header.pack_propagate(False)

        left = tk.Frame(header, bg=COLORS['bg_dark'])
        left.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.dashboard.lbl_monitor_dot = tk.Label(left, text="●", font=("Segoe UI", 10), bg=COLORS['bg_dark'], fg=COLORS['text_dim'])
        self.dashboard.lbl_monitor_dot.pack(side=tk.LEFT, pady=12)
        self.dashboard.lbl_monitor_text = tk.Label(left, text=" Idle", font=self.fonts['header'], bg=COLORS['bg_dark'], fg=COLORS['text_dim'])
        self.dashboard.lbl_monitor_text.pack(side=tk.LEFT, pady=12)

        right = tk.Frame(header, bg=COLORS['bg_dark'])
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=10)

        self.dashboard.btn_sniffer = tk.Label(right, text="  ▶  Start Sniffing  ", font=self.fonts['btn'], bg=COLORS['btn_start'], fg="white", padx=16, pady=6, cursor="hand2")
        self.dashboard.btn_sniffer.pack(side=tk.RIGHT, pady=9)
        self.dashboard.btn_sniffer.bind("<Button-1>", lambda e: self.dashboard.toggle_sniffer())
        self.dashboard.btn_sniffer.bind("<Enter>", lambda e: self.dashboard.btn_sniffer.configure(bg='#1a7a3d' if not self.dashboard.is_sniffing else '#b91c1c'))
        self.dashboard.btn_sniffer.bind("<Leave>", lambda e: self.dashboard.btn_sniffer.configure(bg=COLORS['btn_start'] if not self.dashboard.is_sniffing else COLORS['btn_stop']))

        self.dashboard.lbl_clock = tk.Label(right, text="00:00:00", font=self.fonts['clock'], bg=COLORS['bg_dark'], fg=COLORS['text_secondary'])
        self.dashboard.lbl_clock.pack(side=tk.RIGHT, padx=(0, 20), pady=12)
        tk.Label(right, text="🕐", font=("Segoe UI", 12), bg=COLORS['bg_dark'], fg=COLORS['text_dim']).pack(side=tk.RIGHT, pady=12)

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

        self.dashboard.stat_labels = {}
        for title, key, color in cards_config:
            card = tk.Frame(row, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1, padx=18, pady=12)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

            accent = tk.Frame(card, bg=color, height=3)
            accent.pack(fill=tk.X, pady=(0, 10))

            tk.Label(card, text=title, font=self.fonts['stat_lbl'], bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(anchor=tk.W)

            num_lbl = tk.Label(card, text="0", font=self.fonts['stat_num'], bg=COLORS['bg_card'], fg=color)
            num_lbl.pack(anchor=tk.W, pady=(2, 0))
            self.dashboard.stat_labels[key] = num_lbl

    def _build_alerts_table(self, parent):
        section = tk.Frame(parent, bg=COLORS['bg_darkest'])
        section.pack(fill=tk.X, padx=15, pady=(0, 4))
        tk.Label(section, text="Recent Alerts", font=("Segoe UI", 13, "bold"), bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)
        self.dashboard.lbl_alert_count = tk.Label(section, text="0 alerts", font=self.fonts['stat_lbl'], bg=COLORS['bg_darkest'], fg=COLORS['text_dim'])
        self.dashboard.lbl_alert_count.pack(side=tk.RIGHT)

        table_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 6))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Treeview", background=COLORS['bg_card'], foreground=COLORS['text_primary'], fieldbackground=COLORS['bg_card'], borderwidth=0, font=self.fonts['table'], rowheight=32)
        style.configure("Dark.Treeview.Heading", background=COLORS['bg_dark'], foreground=COLORS['text_secondary'], borderwidth=0, font=self.fonts['table_header'], relief="flat")
        style.map("Dark.Treeview", background=[("selected", COLORS['hover'])], foreground=[("selected", COLORS['accent_cyan'])])
        style.map("Dark.Treeview.Heading", background=[("active", COLORS['border'])])

        columns = ("time", "severity", "src_ip", "dst_ip", "attack", "confidence")
        self.dashboard.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Dark.Treeview", selectmode="browse")

        self.dashboard.tree.heading("time", text="Time")
        self.dashboard.tree.heading("severity", text="Severity")
        self.dashboard.tree.heading("src_ip", text="Source IP")
        self.dashboard.tree.heading("dst_ip", text="Destination IP")
        self.dashboard.tree.heading("attack", text="Attack Type")
        self.dashboard.tree.heading("confidence", text="Confidence")

        self.dashboard.tree.column("time", width=150, minwidth=120)
        self.dashboard.tree.column("severity", width=90, minwidth=70, anchor=tk.CENTER)
        self.dashboard.tree.column("src_ip", width=140, minwidth=100)
        self.dashboard.tree.column("dst_ip", width=140, minwidth=100)
        self.dashboard.tree.column("attack", width=180, minwidth=120)
        self.dashboard.tree.column("confidence", width=90, minwidth=70, anchor=tk.CENTER)

        self.dashboard.tree.tag_configure("High", foreground=COLORS['accent_red'])
        self.dashboard.tree.tag_configure("Medium", foreground=COLORS['accent_amber'])
        self.dashboard.tree.tag_configure("Low", foreground=COLORS['accent_green'])

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.dashboard.tree.yview)
        self.dashboard.tree.configure(yscrollcommand=scrollbar.set)
        self.dashboard.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.dashboard.lbl_empty = tk.Label(table_frame, text="No alerts yet — start the sniffer to begin monitoring", font=("Segoe UI", 11), bg=COLORS['bg_card'], fg=COLORS['text_dim'])
        self.dashboard.lbl_empty.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    def _build_chart(self, parent):
        section = tk.Frame(parent, bg=COLORS['bg_darkest'])
        section.pack(fill=tk.X, pady=(0, 4))
        tk.Label(section, text="Attack Distribution", font=("Segoe UI", 13, "bold"), bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        chart_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        chart_frame.pack(fill=tk.BOTH, expand=True)

        self.fig = Figure(figsize=(4.5, 3), facecolor=COLORS['bg_card'])
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor(COLORS['bg_card'])
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.update_chart()

    def update_chart(self):
        self.ax.clear()
        
        if not self.dashboard.alert_counts:
            self.ax.text(0.5, 0.5, "No Data", color=COLORS['text_dim'], ha='center', va='center', fontsize=12)
            self.ax.axis('off')
        else:
            labels = list(self.dashboard.alert_counts.keys())
            sizes = list(self.dashboard.alert_counts.values())
            
            palette = [COLORS['accent_blue'], COLORS['accent_amber'], COLORS['accent_red'], COLORS['accent_cyan'], COLORS['accent_green'], '#a855f7', '#ec4899']
            
            ATTACK_COLORS = {'DoS': COLORS['accent_red'], 'DDoS': '#991b1b', 'Brute Force': COLORS['accent_amber'], 'Port Scanning': COLORS['accent_blue'], 'Bots': '#a855f7', 'Web Attacks': '#ec4899'}
            
            colors = [ATTACK_COLORS.get(label, palette[i % len(palette)]) for i, label in enumerate(labels)]
                
            pie_result = self.ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90, textprops={'color': '#ffffff', 'fontsize': 10}, labeldistance=0.95, pctdistance=0.75, radius=1.0, wedgeprops={'linewidth': 1, 'edgecolor': COLORS['bg_card']})
            
            if isinstance(pie_result, tuple):
                wedges = pie_result[0]
                autotexts = pie_result[2] if len(pie_result) >= 3 else []
            else:
                wedges = getattr(pie_result, 'patches', [])
                autotexts = getattr(pie_result, 'autotexts', None)
                if autotexts is None:
                    autotexts = getattr(pie_result, 'texts', [])

            flattened_autotexts = []
            for item in autotexts:
                if isinstance(item, (list, tuple)):
                    flattened_autotexts.extend(item)
                else:
                    flattened_autotexts.append(item)

            for autotext in flattened_autotexts:
                if hasattr(autotext, 'set_color'):
                    autotext.set_color('#ffffff')
                    autotext.set_fontsize(10)

            from matplotlib.patches import Patch
            legend_handles = [Patch(facecolor=colors[i], edgecolor=COLORS['bg_card']) for i in range(len(labels))]
            legend = self.ax.legend(legend_handles, labels, title='Attack Type', loc="lower center", bbox_to_anchor=(0.5, 0.95), ncol=min(len(labels), 3), frameon=True, framealpha=0.95, edgecolor=COLORS['border'], labelcolor='#ffffff', fontsize=10, title_fontsize=11)
            legend.get_frame().set_facecolor(COLORS['bg_card'])
            legend.get_title().set_color('#ffffff')
            for text in legend.get_texts():
                text.set_color('#ffffff')

            self.ax.axis('equal')
            
        self.fig.subplots_adjust(left=0.05, right=0.95, top=0.92, bottom=0.05)
        self.canvas.draw()

    def _build_log_panel(self, parent):
        log_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        log_frame.pack(fill=tk.X, padx=15, pady=(0, 10))

        log_header = tk.Frame(log_frame, bg=COLORS['bg_dark'])
        log_header.pack(fill=tk.X)
        tk.Label(log_header, text="  ⌨  Live Log", font=("Segoe UI", 10, "bold"), bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, pady=5)

        self.dashboard.log_text = tk.Text(log_frame, bg=COLORS['log_bg'], fg=COLORS['accent_green'], font=self.fonts['log'], height=12, wrap=tk.WORD, borderwidth=0, highlightthickness=0, insertbackground=COLORS['accent_green'], selectbackground=COLORS['border_light'])
        self.dashboard.log_text.pack(fill=tk.X)
        self.dashboard.log_text.configure(state=tk.DISABLED)

        self.dashboard.log_text.tag_configure("info", foreground=COLORS['accent_green'])
        self.dashboard.log_text.tag_configure("alert", foreground=COLORS['accent_red'], font=("Consolas", 9, "bold"))
        self.dashboard.log_text.tag_configure("warning", foreground=COLORS['accent_amber'])
        self.dashboard.log_text.tag_configure("system", foreground=COLORS['accent_cyan'])

        self.dashboard._log("System initialized. Ready to sniff.\n", "system")
