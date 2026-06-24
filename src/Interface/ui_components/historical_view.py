import tkinter as tk
from tkinter import ttk
from .style_constants import COLORS, SEVERITY_MAP, get_fonts

class HistoricalView:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_historical_ui()

    def _build_historical_ui(self):
        parent = self.frame
        # Header
        header = tk.Frame(parent, bg=COLORS['bg_dark'], height=50)
        header.pack(fill=tk.X, padx=15, pady=(12, 0))
        header.pack_propagate(False)
        tk.Label(header, text="Historical Logs", font=self.fonts['header'], bg=COLORS['bg_dark'], fg=COLORS['text_primary']).pack(side=tk.LEFT, padx=15, pady=12)

        # Search Bar Area
        search_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        search_frame.pack(fill=tk.X, padx=15, pady=(15, 0))
        
        tk.Label(search_frame, text="Search IP:", font=self.fonts['table'], bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, padx=(15, 5), pady=15)
        self.ent_search_ip = tk.Entry(search_frame, font=self.fonts['table'], bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT, width=20)
        self.ent_search_ip.pack(side=tk.LEFT, ipady=4)
        
        tk.Label(search_frame, text="Attack Type:", font=self.fonts['table'], bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(side=tk.LEFT, padx=(20, 5), pady=15)
        self.cb_search_attack = ttk.Combobox(search_frame, values=["All"] + list(SEVERITY_MAP.keys()), state="readonly", font=self.fonts['table'], width=15)
        self.cb_search_attack.set("All")
        self.cb_search_attack.pack(side=tk.LEFT, ipady=2)
        
        btn_search = tk.Button(search_frame, text="Search", font=self.fonts['btn'], bg=COLORS['accent_blue'], fg="white", relief=tk.FLAT, cursor="hand2", command=self._do_historical_search)
        btn_search.pack(side=tk.LEFT, padx=(20, 15), ipady=2, ipadx=10)

        # Table container
        table_frame = tk.Frame(parent, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        columns = ("time", "severity", "src_ip", "dst_ip", "attack", "confidence")
        self.dashboard.hist_tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Dark.Treeview", selectmode="browse")

        self.dashboard.hist_tree.heading("time",       text="Time")
        self.dashboard.hist_tree.heading("severity",   text="Severity")
        self.dashboard.hist_tree.heading("src_ip",     text="Source IP")
        self.dashboard.hist_tree.heading("dst_ip",     text="Destination IP")
        self.dashboard.hist_tree.heading("attack",     text="Attack Type")
        self.dashboard.hist_tree.heading("confidence", text="Confidence")

        self.dashboard.hist_tree.column("time",       width=150, minwidth=120)
        self.dashboard.hist_tree.column("severity",   width=90,  minwidth=70, anchor=tk.CENTER)
        self.dashboard.hist_tree.column("src_ip",     width=140, minwidth=100)
        self.dashboard.hist_tree.column("dst_ip",     width=140, minwidth=100)
        self.dashboard.hist_tree.column("attack",     width=180, minwidth=120)
        self.dashboard.hist_tree.column("confidence", width=90,  minwidth=70, anchor=tk.CENTER)

        self.dashboard.hist_tree.tag_configure("High",   foreground=COLORS['accent_red'])
        self.dashboard.hist_tree.tag_configure("Medium", foreground=COLORS['accent_amber'])
        self.dashboard.hist_tree.tag_configure("Low",    foreground=COLORS['accent_green'])

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.dashboard.hist_tree.yview)
        self.dashboard.hist_tree.configure(yscrollcommand=scrollbar.set)

        self.dashboard.hist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Action Area
        action_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        action_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.btn_scan = tk.Button(action_frame, text="🔍 In-Depth IP Scan", font=self.fonts['btn'], bg=COLORS['accent_cyan'], fg="black", relief=tk.FLAT, cursor="hand2", command=self._do_indepth_scan)
        self.btn_scan.pack(side=tk.RIGHT, ipady=4, ipadx=10)

    def refresh_historical_table(self, logs=None):
        if logs is None:
            logs = self.dashboard.historical_logs
            
        for item in self.dashboard.hist_tree.get_children():
            self.dashboard.hist_tree.delete(item)
            
        for log in reversed(logs):
            self.dashboard.hist_tree.insert("", tk.END, values=(
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
        for log in self.dashboard.historical_logs:
            match_ip = (query_ip == "" or query_ip in log.get('src_ip', '') or query_ip in log.get('dst_ip', ''))
            match_attack = (query_attack == "All" or query_attack == log.get('attack_type', ''))
            
            if match_ip and match_attack:
                results.append(log)
                
        self.refresh_historical_table(results)

    def _do_indepth_scan(self):
        selected = self.dashboard.hist_tree.selection()
        if not selected:
            return
            
        item = self.dashboard.hist_tree.item(selected[0])
        src_ip_full = str(item['values'][2])
        src_ip = src_ip_full.split(':')[0]
        
        ip_logs = []
        for log in self.dashboard.historical_logs:
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
        
        win = tk.Toplevel(self.dashboard.root)
        win.title(f"In-Depth Scan: {src_ip}")
        win.geometry("400x300")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.dashboard.root)
        win.grab_set()
        
        tk.Label(win, text=f"Analysis for {src_ip}", font=("Segoe UI", 14, "bold"), bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(pady=(20, 10))
        
        stats_frame = tk.Frame(win, bg=COLORS['bg_dark'], padx=20, pady=20)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        tk.Label(stats_frame, text=f"Total Attacks: {total}", font=self.fonts['table_header'], bg=COLORS['bg_dark'], fg=COLORS['accent_cyan']).pack(anchor=tk.W, pady=2)
        tk.Label(stats_frame, text=f"First Seen: {first_seen}", font=self.fonts['table'], bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=2)
        tk.Label(stats_frame, text=f"Last Seen: {last_seen}", font=self.fonts['table'], bg=COLORS['bg_dark'], fg=COLORS['text_secondary']).pack(anchor=tk.W, pady=2)
        
        tk.Label(stats_frame, text="Attack Types Profile:", font=self.fonts['table_header'], bg=COLORS['bg_dark'], fg=COLORS['text_primary']).pack(anchor=tk.W, pady=(10, 2))
        for t, c in types.items():
            tk.Label(stats_frame, text=f"  • {t}: {c}", font=self.fonts['table'], bg=COLORS['bg_dark'], fg=COLORS['accent_amber']).pack(anchor=tk.W)
