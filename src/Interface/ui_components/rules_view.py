import tkinter as tk
from tkinter import ttk
import time
from database.connection import session
from database.models import Rule
from .style_constants import COLORS, get_fonts

class RulesView:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_rules_ui()

    def _build_rules_ui(self):
        parent = self.frame
        header = tk.Frame(parent, bg=COLORS['bg_darkest'])
        header.pack(fill=tk.X, padx=30, pady=(25, 10))
        tk.Label(header, text="Rule Management", font=("Segoe UI", 24, "bold"),
                 bg=COLORS['bg_darkest'], fg=COLORS['text_primary']).pack(side=tk.LEFT)

        self.dashboard.rules_control_frame = tk.Frame(parent, bg=COLORS['bg_darkest'])
        self.dashboard.rules_control_frame.pack(fill=tk.X, padx=30, pady=(0, 10))
        
        tk.Button(self.dashboard.rules_control_frame, text="➕ Add New Rule", font=self.fonts['btn'], bg=COLORS['accent_blue'], fg="white", 
                  relief=tk.FLAT, cursor="hand2", command=lambda: self._show_rule_form()).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
        
        tk.Button(self.dashboard.rules_control_frame, text="✏️ Edit", font=self.fonts['btn'], bg=COLORS['bg_card'], fg=COLORS['text_primary'], 
                  relief=tk.FLAT, cursor="hand2", command=self._edit_selected_rule).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
                  
        tk.Button(self.dashboard.rules_control_frame, text="⏸ Pause / Resume", font=self.fonts['btn'], bg=COLORS['bg_card'], fg=COLORS['text_primary'], 
                  relief=tk.FLAT, cursor="hand2", command=self._toggle_rule_status).pack(side=tk.LEFT, padx=(0, 10), ipady=4, ipadx=10)
                  
        tk.Button(self.dashboard.rules_control_frame, text="🗑️ Delete", font=self.fonts['btn'], bg=COLORS['btn_stop'], fg="white", 
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
        
    def refresh_rules_table(self):
        if not hasattr(self, 'rules_tree'): return
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        for rule in self.dashboard.rules:
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
        win = tk.Toplevel(self.dashboard.root)
        win.title("Rule Configuration")
        win.geometry("500x550")
        win.configure(bg=COLORS['bg_card'])
        win.transient(self.dashboard.root)
        win.grab_set()

        rule = self.dashboard.rules[rule_idx] if rule_idx is not None else {}

        tk.Label(win, text="Rule Name:", font=self.fonts['table_header'], bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(20, 5))
        var_name = tk.StringVar(value=rule.get("name", ""))
        tk.Entry(win, textvariable=var_name, font=self.fonts['table'], bg=COLORS['bg_dark'], fg="white", insertbackground="white").pack(fill=tk.X, padx=20)

        tk.Label(win, text="Description:", font=self.fonts['table_header'], bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(15, 5))
        text_desc = tk.Text(win, height=3, font=self.fonts['table'], bg=COLORS['bg_dark'], fg="white", insertbackground="white")
        text_desc.pack(fill=tk.X, padx=20)
        text_desc.insert(1.0, rule.get("description", ""))

        logic_frame = tk.LabelFrame(win, text="Detection Logic", font=self.fonts['table_header'], bg=COLORS['bg_card'], fg=COLORS['accent_cyan'], padx=10, pady=10)
        logic_frame.pack(fill=tk.X, padx=20, pady=15)
        
        logic = rule.get("logic", {})
        
        tk.Label(logic_frame, text="Target Field:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=0, column=0, sticky=tk.W, pady=5)
        var_field = tk.StringVar(value=logic.get("field", "Source IP"))
        ttk.Combobox(logic_frame, textvariable=var_field, values=[
            "Source IP", "Dest IP", "Port", "Protocol", "Packet Count",
            "Payload Regex", "Connection Attempts / min", "Unique Ports Scanned / 10s", "Packets to Dest Port / 10s"
        ], state="readonly").grid(row=0, column=1, sticky=tk.EW, padx=10)

        tk.Label(logic_frame, text="Condition:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=1, column=0, sticky=tk.W, pady=5)
        var_cond = tk.StringVar(value=logic.get("condition", "Equals"))
        ttk.Combobox(logic_frame, textvariable=var_cond, values=["Equals", "Contains", "Greater Than", "Less Than"], state="readonly").grid(row=1, column=1, sticky=tk.EW, padx=10)

        tk.Label(logic_frame, text="Value:", bg=COLORS['bg_card'], fg=COLORS['text_primary']).grid(row=2, column=0, sticky=tk.W, pady=5)
        var_val = tk.StringVar(value=logic.get("value", ""))
        tk.Entry(logic_frame, textvariable=var_val, bg=COLORS['bg_dark'], fg="white", insertbackground="white").grid(row=2, column=1, sticky=tk.EW, padx=10)
        
        logic_frame.columnconfigure(1, weight=1)

        tk.Label(win, text="Action:", font=self.fonts['table_header'], bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(5, 5))
        var_action = tk.StringVar(value=rule.get("action", "Alert High"))
        ttk.Combobox(win, textvariable=var_action, values=["Alert High", "Alert Medium", "Alert Low", "Drop / Block"], state="readonly").pack(fill=tk.X, padx=20)

        tk.Label(win, text="Initial Status:", font=self.fonts['table_header'], bg=COLORS['bg_card'], fg=COLORS['text_primary']).pack(anchor=tk.W, padx=20, pady=(15, 5))
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
                self.dashboard.rules[rule_idx] = new_rule
                event_name = "Rule edited"
            else:
                self.dashboard.rules.append(new_rule)
                event_name = "Rule added"
                
            self.dashboard._save_rules()
            self.refresh_rules_table()
            self.dashboard._save_system_log(event_name, f"{event_name} '{new_rule['name']}'", {"rule_id": new_rule.get('id')})
            win.destroy()

        tk.Button(win, text="💾 Save Rule", font=self.fonts['btn'], bg=COLORS['accent_green'], fg="black", 
                  relief=tk.FLAT, cursor="hand2", command=_save).pack(pady=(30, 20), ipady=5, ipadx=20)
                  
    def _edit_selected_rule(self):
        sel = self.rules_tree.selection()
        if not sel: return
        item = self.rules_tree.item(sel[0])
        rule_id = item['values'][0]
        for i, r in enumerate(self.dashboard.rules):
            if r.get("id") == rule_id:
                self._show_rule_form(i)
                break
                
    def _toggle_rule_status(self):
        sel = self.rules_tree.selection()
        if not sel: return
        item = self.rules_tree.item(sel[0])
        rule_id = item['values'][0]
        for r in self.dashboard.rules:
            if r.get("id") == rule_id:
                r["status"] = "paused" if r.get("status") == "active" else "active"
                break
        self.dashboard._save_rules()
        self.refresh_rules_table()
        
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
                    if self.dashboard.sniffer_service and hasattr(self.dashboard.sniffer_service, 'reload_rules'):
                        self.dashboard.sniffer_service.reload_rules()
        except Exception:
            session.rollback()
            
        self.dashboard.rules = [r for r in self.dashboard.rules if r.get("id") != rule_id]
        self.dashboard._save_system_log("Rule deleted", f"Deleted rule ID {rule_id}", {"rule_id": rule_id})
        self.refresh_rules_table()
