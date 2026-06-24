import tkinter as tk
from tkinter import ttk
from .style_constants import COLORS, get_fonts

class TrafficMonitorView:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_traffic_monitor_ui()

    def _build_traffic_monitor_ui(self):
        parent = self.frame
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
                                     font=self.fonts['log'], borderwidth=0, highlightthickness=0)
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
                                       font=self.fonts['log'], borderwidth=0, highlightthickness=1, highlightbackground=COLORS['border'])
        self.tm_text_payload.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.tm_text_payload.config(state=tk.DISABLED)

        actions_frame = tk.Frame(self.tm_right_frame, bg=COLORS['bg_card'])
        actions_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.btn_ack = tk.Button(actions_frame, text="✅ Acknowledge", font=self.fonts['btn'], bg=COLORS['bg_dark'], fg="white", 
                                 relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("ack"))
        self.btn_ack.pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
        
        self.btn_fp = tk.Button(actions_frame, text="❌ False Positive", font=self.fonts['btn'], bg=COLORS['bg_dark'], fg="white", 
                                relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("fp"))
        self.btn_fp.pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)

        self.btn_block = tk.Button(actions_frame, text="🚫 Block Source IP", font=self.fonts['btn'], bg=COLORS['btn_stop'], fg="white", 
                                   relief=tk.FLAT, cursor="hand2", command=lambda: self._handle_alert_action("block"))
        self.btn_block.pack(side=tk.RIGHT, ipady=4, ipadx=10)
        
        self._toggle_tm_actions(False)

    def refresh_traffic_monitor(self):
        self.tm_listbox.delete(0, tk.END)
        self.tm_active_indices = []
        for i, alt in enumerate(self.dashboard.detailed_alerts):
            if alt["status"] == "active":
                self.tm_listbox.insert(tk.END, f"[{alt['severity']}] {alt['src_ip']} - {alt['attack_type']}")
                self.tm_active_indices.append(i)
                
    def _on_tm_alert_select(self, event):
        sel = self.tm_listbox.curselection()
        if not sel:
            self._toggle_tm_actions(False)
            return
        idx = self.tm_active_indices[sel[0]]
        alt = self.dashboard.detailed_alerts[idx]
        self.tm_selected_index = idx
        
        self.tm_lbl_title.config(text=f"Alert {alt.get('id', 'N/A')} Details")
        self.tm_lbl_info.config(text=f"Time: {alt['timestamp']}\nSource: {alt['src_ip']}\nDestination: {alt['dst_ip']}\nType: {alt['attack_type']}\nConfidence: {alt['confidence']}")
        mech = alt.get("details", {}).get("rule_triggered", "Unknown Mechanism")
        self.tm_lbl_mechanism.config(text=f"Detection Mechanism: {mech}")
        
        self._toggle_tm_actions(True)
        self._update_payload_view()
        
    def _update_payload_view(self):
        if not hasattr(self, 'tm_selected_index') or self.tm_selected_index is None:
            return
        alt = self.dashboard.detailed_alerts[self.tm_selected_index]
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
        alt = self.dashboard.detailed_alerts[self.tm_selected_index]
        if action == "ack":
            alt["status"] = "acknowledged"
            self.dashboard._log(f"Alert {alt.get('id', 'N/A')} marked as acknowledged.", "success")
        elif action == "fp":
            alt["status"] = "false_positive"
            self.dashboard._log(f"Alert {alt.get('id', 'N/A')} marked as false positive.", "warning")
        elif action == "block":
            alt["status"] = "blocked"
            self.dashboard._log(f"Source IP {alt['src_ip']} blocked.", "alert")
            
        self.tm_selected_index = None
        self.tm_lbl_title.config(text="Select an alert to view details")
        self.tm_lbl_info.config(text="")
        self.tm_lbl_mechanism.config(text="")
        self.tm_text_payload.config(state=tk.NORMAL)
        self.tm_text_payload.delete(1.0, tk.END)
        self.tm_text_payload.config(state=tk.DISABLED)
        self._toggle_tm_actions(False)
        self.refresh_traffic_monitor()
        
    def _toggle_tm_actions(self, enabled):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.btn_ack.config(state=state)
        self.btn_fp.config(state=state)
        self.btn_block.config(state=state)
