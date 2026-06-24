import sys
import os
import threading
import time
from datetime import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

import tkinter as tk
from tkinter import ttk, font as tkfont
import matplotlib
matplotlib.use("TkAgg")

from sniffer_service import SnifferService
from net_utils import get_active_interface_name
import config
from database.connection import session
from database.models import Rule, Alert, TrafficLog, User

from ui_components.style_constants import COLORS, SEVERITY_MAP, SEVERITY_COLORS, get_fonts
from ui_components.login_view import LoginView
from ui_components.sidebar import Sidebar
from ui_components.dashboard_view import DashboardView
from ui_components.historical_view import HistoricalView
from ui_components.traffic_monitor_view import TrafficMonitorView
from ui_components.rules_view import RulesView

INTERFACE_NAME = get_active_interface_name()

class IDSDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("IntrusionSense — IDS Dashboard")
        self.root.geometry("1280x780")
        self.root.minsize(1100, 650)
        self.root.configure(bg=COLORS['bg_darkest'])

        self.sniffer_thread = None
        self.sniffer_service = None
        self.is_sniffing = False
        self.alerts = []
        self.detailed_alerts = []
        self.packets_analyzed = 0
        self.stats = {'total': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        self.model_loaded = False
        self.alert_counts = {}
        
        self.historical_logs = []
        self._load_historical_logs()
        
        self.rules = []
        self._load_rules()

        self.fonts = get_fonts()
        self.nav_buttons = [] # Populated by Sidebar

        self.container = tk.Frame(self.root, bg=COLORS['bg_darkest'])
        self.container.pack(fill=tk.BOTH, expand=True)

        self.frame_login = tk.Frame(self.container, bg=COLORS['bg_darkest'])
        self.frame_main = tk.Frame(self.container, bg=COLORS['bg_darkest'])
        
        # Build views
        self.login_view = LoginView(self.frame_login, self)
        
        # --- Main UI layout ---
        self.sidebar_frame = tk.Frame(self.frame_main, bg=COLORS['bg_sidebar'], width=240)
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar_frame.pack_propagate(False)
        self.sidebar_view = Sidebar(self.sidebar_frame, self)
        
        self.main_area = tk.Frame(self.frame_main, bg=COLORS['bg_darkest'])
        self.main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self.frame_dashboard = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_historical = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_traffic_monitor = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        self.frame_rules = tk.Frame(self.main_area, bg=COLORS['bg_darkest'])
        
        self.dashboard_view = DashboardView(self.frame_dashboard, self)
        self.historical_view = HistoricalView(self.frame_historical, self)
        self.traffic_monitor_view = TrafficMonitorView(self.frame_traffic_monitor, self)
        self.rules_view = RulesView(self.frame_rules, self)
        
        self.frame_dashboard.pack(fill=tk.BOTH, expand=True)
        self.current_view = "Dashboard"

        self.frame_login.pack(fill=tk.BOTH, expand=True)
        self._tick_clock()
        self.root.bind("<Button-1>", self._clear_tree_selection)
        
    def _clear_tree_selection(self, event):
        widget = event.widget
        w_class = widget.winfo_class()
        if w_class in ['Treeview', 'Scrollbar']: return
        if hasattr(self.historical_view, 'btn_scan') and widget == self.historical_view.btn_scan: return
        if hasattr(self, 'tree'):
            try: self.tree.selection_remove(self.tree.selection())
            except Exception: pass
        if hasattr(self, 'hist_tree'):
            try: self.hist_tree.selection_remove(self.hist_tree.selection())
            except Exception: pass
            
    def _tick_clock(self):
        now = datetime.now().strftime("%H:%M:%S")
        if hasattr(self, 'lbl_clock'):
            self.lbl_clock.configure(text=now)
        self.root.after(1000, self._tick_clock)

    def _open_settings(self, event=None):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("300x150")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text="Layer 1 Threshold:", font=("Segoe UI", 10, "bold"), bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(pady=(20, 5))

        if not hasattr(self, 'threshold_var'):
            self.threshold_var = tk.DoubleVar(value=0.65)
        
        def on_threshold_change(val):
            if self.sniffer_service and hasattr(self.sniffer_service, 'engine'):
                self.sniffer_service.engine.l1_threshold = float(val)
                
        slider = tk.Scale(win, from_=0.01, to=0.99, resolution=0.01, orient=tk.HORIZONTAL, variable=self.threshold_var, command=on_threshold_change, bg=COLORS['bg_card'], fg=COLORS['accent_cyan'], activebackground=COLORS['accent_cyan'], highlightthickness=0, bd=0, sliderrelief=tk.RAISED, troughcolor=COLORS['border_light'])
        slider.pack(fill=tk.X, padx=20)

    def _switch_view(self, view_name):
        self.current_view = view_name
        self.frame_dashboard.pack_forget()
        self.frame_historical.pack_forget()
        self.frame_traffic_monitor.pack_forget()
        self.frame_rules.pack_forget()

        if view_name == "Dashboard":
            self.frame_dashboard.pack(fill=tk.BOTH, expand=True)
            self.dashboard_view.update_chart()
        elif view_name == "Historical Logs":
            self.historical_view.refresh_historical_table()
            self.frame_historical.pack(fill=tk.BOTH, expand=True)
        elif view_name == "Traffic Monitor":
            self.traffic_monitor_view.refresh_traffic_monitor()
            self.frame_traffic_monitor.pack(fill=tk.BOTH, expand=True)
        elif view_name == "Rules":
            self.rules_view.refresh_rules_table()
            self.frame_rules.pack(fill=tk.BOTH, expand=True)

        for container, label in self.nav_buttons:
            is_active = (label == view_name)
            container.is_active = is_active
            
            bg = COLORS['active_nav'] if is_active else COLORS['bg_sidebar']
            fg = COLORS['accent_cyan'] if is_active else COLORS['text_secondary']
            left_accent = COLORS['accent_cyan'] if is_active else COLORS['bg_sidebar']
            font = self.fonts['nav_bold'] if is_active else self.fonts['nav']
            
            children = container.winfo_children()
            if len(children) >= 2:
                accent = children[0]
                btn_lbl = children[1]
                accent.configure(bg=left_accent)
                btn_lbl.configure(bg=bg, fg=fg, font=font)

    def _log(self, message, tag="info"):
        if hasattr(self, 'log_text'):
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, message, tag)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

    def _poll_packets(self):
        if self.sniffer_service and self.is_sniffing:
            self.packets_analyzed = self.sniffer_service.packet_count
            self._update_stats()
            self.root.after(500, self._poll_packets)

    def _update_stats(self):
        if not hasattr(self, 'stat_labels'): return
        self.stat_labels['total'].configure(text=str(self.stats['total']))
        self.stat_labels['High'].configure(text=str(self.stats['High']))
        self.stat_labels['Medium'].configure(text=str(self.stats['Medium']))
        self.stat_labels['Low'].configure(text=str(self.stats['Low']))
        self.stat_labels['pkts'].configure(text=str(self.packets_analyzed))
        if hasattr(self, 'lbl_alert_count'):
            self.lbl_alert_count.configure(text=f"{self.stats['total']} alerts")

    def _add_alert(self, src_ip, dst_ip, attack_type, confidence_str, details=None):
        severity = SEVERITY_MAP.get(attack_type, "Medium")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if hasattr(self, 'lbl_empty'):
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
            self.traffic_monitor_view.refresh_traffic_monitor()

        count = self.alert_counts.get(attack_type, 0) + 1
        self.alert_counts[attack_type] = count

        if hasattr(self, 'tree'):
            if count >= 16:
                group_iid = f"group_{attack_type}"
                if not self.tree.exists(group_iid):
                    self.tree.insert("", 0, iid=group_iid, values=("Multiple", severity, "Various", "Various", f"{attack_type} Alerts", f"Total: {count}"), tags=(severity,))
                    for item in self.tree.get_children(""):
                        if item != group_iid and self.tree.item(item, "values") and self.tree.item(item, "values")[4] == attack_type:
                            self.tree.move(item, group_iid, 0)
                else:
                    self.tree.item(group_iid, values=("Multiple", severity, "Various", "Various", f"{attack_type} Alerts", f"Total: {count}"))
                    self.tree.move(group_iid, "", 0)
                
                self.tree.insert(group_iid, 0, values=(timestamp, severity, src_ip, dst_ip, attack_type, confidence_str), tags=(severity,))
            else:
                self.tree.insert("", 0, values=(timestamp, severity, src_ip, dst_ip, attack_type, confidence_str),
                                 tags=(severity,))

        self.stats['total'] += 1
        self.stats[severity] = self.stats.get(severity, 0) + 1
        self._update_stats()
        
        if hasattr(self, 'dashboard_view'):
            self.dashboard_view.update_chart()

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
        if "ALERT!" in message:
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
            self.sniffer_service.stop()
            self.is_sniffing = False
            self.btn_sniffer.configure(text="  ▶  Start Sniffing  ", bg=COLORS['btn_start'])
            self.lbl_sniffer_status.configure(text="● Stopped", fg=COLORS['accent_red'])
            self.lbl_monitor_dot.configure(fg=COLORS['text_dim'])
            self.lbl_monitor_text.configure(text=" Idle", fg=COLORS['text_dim'])
            self._log("Sniffer stopped.\n", "warning")
        else:
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
                    "details": {}
                })
        except Exception as e:
            print(f"Error loading historical logs from DB: {e}")

    def _save_historical_log(self, log_entry, details=None):
        try:
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
            session.flush()

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
            
    def _load_rules(self):
        self.rules = []
        try:
            db_rules = session.query(Rule).all()
            known_fields = [
                "Source IP", "Dest IP", "Port", "Protocol", "Packet Count",
                "Payload Regex", "Connection Attempts / min",
                "Unique Ports Scanned / 10s", "Packets to Dest Port / 10s"
            ]
            for r in db_rules:
                text = r.ConditionText.strip() if r.ConditionText else ""
                field = ""
                value = ""
                
                # Extract field correctly by checking against known fields
                for kf in known_fields:
                    if text.startswith(kf):
                        field = kf
                        value = text[len(kf):].strip()
                        break
                
                # Fallback if it doesn't match known fields
                if not field:
                    field = text.split(' ', 1)[0] if text else ""
                    value = text.split(' ', 1)[1] if text and ' ' in text else ""

                self.rules.append({
                    "id": r.RuleID,
                    "name": r.RuleName,
                    "description": r.Description,
                    "action": r.Severity,
                    "status": "active" if r.IsActive else "paused",
                    "logic": {
                        "field": field,
                        "condition": "",
                        "value": value
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
                
                if isinstance(rule_id, int):
                    db_rule = session.get(Rule, rule_id)
                    if db_rule:
                        db_rule.RuleName = r.get("name")
                        db_rule.Description = r.get("description")
                        db_rule.Severity = r.get("action")
                        db_rule.ConditionText = condition_text
                        db_rule.IsActive = is_active
                else:
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
                    r["id"] = new_rule.RuleID
                    
            session.commit()
            if self.sniffer_service and hasattr(self.sniffer_service, 'reload_rules'):
                self.sniffer_service.reload_rules()
        except Exception as e:
            print(f"Error saving rules: {str(e)}")
            session.rollback()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IDSDashboard(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)