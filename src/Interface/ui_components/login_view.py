import tkinter as tk
import hashlib
from database.models import User
from database.connection import session
from .style_constants import COLORS, get_fonts

class LoginView:
    def __init__(self, parent_frame, dashboard):
        self.frame = parent_frame
        self.dashboard = dashboard
        self.fonts = get_fonts()
        self._build_login()

    def _build_login(self):
        box = tk.Frame(self.frame, bg=COLORS['bg_card'], highlightbackground=COLORS['border'], highlightthickness=1, padx=40, pady=40)
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        brand_frame = tk.Frame(box, bg=COLORS['bg_card'], width=200, height=40)
        brand_frame.pack(pady=(0, 5))
        brand_frame.pack_propagate(False)

        tk.Label(brand_frame, text="🛡️", font=("Segoe UI", 20),
                 bg=COLORS['bg_card'], fg=COLORS['accent_cyan']).place(x=12, rely=0.5, anchor=tk.W)
        tk.Label(brand_frame, text="IntrusionSense", font=self.fonts['brand'],
                 bg=COLORS['bg_card'], fg=COLORS['accent_cyan']).place(x=46, rely=0.5, anchor=tk.W)
        tk.Label(box, text="Admin Authentication", font=self.fonts['header'], bg=COLORS['bg_card'], fg=COLORS['text_secondary']).pack(pady=(0, 30))

        tk.Label(box, text="Username", font=self.fonts['stat_lbl'], bg=COLORS['bg_card'], fg=COLORS['text_dim']).pack(anchor=tk.W)
        self.ent_user = tk.Entry(box, font=self.fonts['header'], bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT)
        self.ent_user.pack(fill=tk.X, pady=(5, 15), ipady=5)

        tk.Label(box, text="Password", font=self.fonts['stat_lbl'], bg=COLORS['bg_card'], fg=COLORS['text_dim']).pack(anchor=tk.W)
        self.ent_pass = tk.Entry(box, font=self.fonts['header'], bg=COLORS['bg_dark'], fg=COLORS['text_primary'], insertbackground='white', relief=tk.FLAT, show="*")
        self.ent_pass.pack(fill=tk.X, pady=(5, 25), ipady=5)

        self.lbl_login_err = tk.Label(box, text="", font=self.fonts['stat_lbl'], bg=COLORS['bg_card'], fg=COLORS['accent_red'])
        self.lbl_login_err.pack(pady=(0, 10))

        btn = tk.Button(box, text="Login to Command Center", font=self.fonts['btn'], bg=COLORS['accent_blue'], fg="white", relief=tk.FLAT, cursor="hand2", command=self._do_login)
        btn.pack(fill=tk.X, ipady=8)

    def _do_login(self):
        username = self.ent_user.get()
        pwd = self.ent_pass.get()
        
        hashed_pwd = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
        
        user = session.query(User).filter_by(Username=username).first()
        
        if user and user.PasswordHash == hashed_pwd:
            self.lbl_login_err.config(text="")
            self.dashboard.current_user = user
            self.dashboard.current_role = user.Role
            self.frame.pack_forget()
            
            self._apply_rbac()
            self.dashboard.frame_main.pack(fill=tk.BOTH, expand=True)
        else:
            self.lbl_login_err.config(text="Invalid credentials")

    def _apply_rbac(self):
        # Hide Settings for Manager and SOC Analyst
        if self.dashboard.current_role in ["Manager", "SOC Analyst"]:
            for container, label in self.dashboard.nav_buttons:
                if label == "Settings":
                    container.pack_forget()
                    
        # Disable Rules editing for SOC Analyst
        if self.dashboard.current_role == "SOC Analyst":
            if hasattr(self.dashboard, 'rules_control_frame') and self.dashboard.rules_control_frame:
                for child in self.dashboard.rules_control_frame.winfo_children():
                    try:
                        child['state'] = tk.DISABLED
                    except Exception:
                        pass

    def do_logout(self):
        # Reset current user state
        self.dashboard.current_user = None
        self.dashboard.current_role = None
        
        # Restore RBAC-hidden elements
        for container, label in self.dashboard.nav_buttons:
            if label == "Settings":
                # Restore the Settings nav button
                container.pack(fill=tk.X, pady=2)
                
        if hasattr(self.dashboard, 'rules_control_frame') and self.dashboard.rules_control_frame:
            for child in self.dashboard.rules_control_frame.winfo_children():
                try:
                    child['state'] = tk.NORMAL
                except Exception:
                    pass
            
        # Switch to Dashboard view by default
        self.dashboard._switch_view("Dashboard")
        
        # Clear login form
        self.ent_pass.delete(0, tk.END)
        self.lbl_login_err.config(text="")
        
        # Switch to login screen
        self.dashboard.frame_main.pack_forget()
        self.frame.pack(fill=tk.BOTH, expand=True)
