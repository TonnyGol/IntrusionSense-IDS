import sys
import os

# --- תיקון נתיבים (חובה להיות ראשון!) ---
# משיג את הנתיב של התיקייה הנוכחית (src/Interface)
current_dir = os.path.dirname(os.path.abspath(__file__))
# משיג את הנתיב של התיקייה מעל (src)
parent_dir = os.path.dirname(current_dir)
# מוסיף את src לרשימת המקומות שפייתון מחפש בהם
sys.path.append(parent_dir)

# עכשיו אפשר לייבא דברים שנמצאים ב-src או באותה תיקייה
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess
from sniffer_service import SnifferService # זה נמצא לידנו ב-Interface
from net_utils import get_active_interface_name

# --- הגדרות ---
INTERFACE_NAME = get_active_interface_name()

class IDSDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ AI-Powered IDS Dashboard")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        self.sniffer_thread = None
        self.sniffer_service = None
        self.attack_process = None

        self.setup_ui()

    def setup_ui(self):
        # כותרת
        header = tk.Label(self.root, text="AI INTRUSION DETECTION SYSTEM", 
                          font=("Consolas", 20, "bold"), bg="#1e1e1e", fg="#00ff00")
        header.pack(pady=10)

        # אזור ראשי
        main_frame = tk.Frame(self.root, bg="#1e1e1e")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        # צד שמאל
        left_panel = tk.Frame(main_frame, bg="#2d2d2d", width=250)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=10)

        # צד ימין
        right_panel = tk.Frame(main_frame, bg="#1e1e1e")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # כפתורים
        lbl_defense = tk.Label(left_panel, text="🛡️ DEFENSE CONTROLS", font=("Arial", 12, "bold"), bg="#2d2d2d", fg="white")
        lbl_defense.pack(pady=(20, 10))

        # Select Model Type
        lbl_model = tk.Label(left_panel, text="🧠 AI MODEL", font=("Arial", 10, "bold"), bg="#2d2d2d", fg="lightblue")
        lbl_model.pack(pady=(5, 5))
        
        self.model_var = tk.StringVar(value="rf")
        
        tk.Radiobutton(left_panel, text="Random Forest", variable=self.model_var, value="rf", bg="#2d2d2d", fg="white", selectcolor="#444", activebackground="#2d2d2d").pack(anchor="w", padx=20)
        tk.Radiobutton(left_panel, text="XGBoost", variable=self.model_var, value="xgboost", bg="#2d2d2d", fg="white", selectcolor="#444", activebackground="#2d2d2d").pack(anchor="w", padx=20)
        tk.Radiobutton(left_panel, text="LightGBM", variable=self.model_var, value="lightgbm", bg="#2d2d2d", fg="white", selectcolor="#444", activebackground="#2d2d2d").pack(anchor="w", padx=20)

        self.btn_sniffer = tk.Button(left_panel, text="START SNIFFER", font=("Arial", 10, "bold"), 
                                     bg="green", fg="white", width=20, height=2, command=self.toggle_sniffer)
        self.btn_sniffer.pack(pady=(15, 5))

        tk.Frame(left_panel, height=2, bg="gray").pack(fill=tk.X, pady=20, padx=10)

        lbl_attack = tk.Label(left_panel, text="💀 ATTACK SIMULATION", font=("Arial", 12, "bold"), bg="#2d2d2d", fg="red")
        lbl_attack.pack(pady=(10, 10))

        # כפתורי התקפה
        self.create_attack_btn(left_panel, "LAUNCH DoS ATTACK", "Dos_attack.py")
        self.create_attack_btn(left_panel, "LAUNCH PORTSCAN", "PortScan_attack.py")
        self.create_attack_btn(left_panel, "LAUNCH BRUTE FORCE", "BruteForce_attack.py")
        self.create_attack_btn(left_panel, "LAUNCH WEB ATTACK", "Web_attack.py")

        btn_stop_atk = tk.Button(left_panel, text="⏹ STOP ALL ATTACKS", bg="darkred", fg="white", width=20, 
                                 command=self.stop_attack)
        btn_stop_atk.pack(pady=20)

        # לוגים
        self.log_area = scrolledtext.ScrolledText(right_panel, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log("Welcome to IDS Dashboard. System ready.", "white")

    def create_attack_btn(self, parent, text, script):
        btn = tk.Button(parent, text=text, bg="#444", fg="white", width=20, 
                        command=lambda: self.run_attack_script(script))
        btn.pack(pady=5)

    def log(self, message, color="#00ff00"):
        self.log_area.insert(tk.END, message)
        if "ALERT" in message:
            last_line_index = self.log_area.index("end-2c linestart")
            self.log_area.tag_add("alert", last_line_index, "end-1c")
            self.log_area.tag_config("alert", foreground="red", background="#220000")
        self.log_area.see(tk.END)

    def toggle_sniffer(self):
        if self.sniffer_service and self.sniffer_service.running:
            self.sniffer_service.stop()
            self.btn_sniffer.config(text="START SNIFFER", bg="green")
            self.log("Stopping sniffer...\n", "yellow")
        else:
            selected_model = self.model_var.get()
            try:
                self.sniffer_service = SnifferService(INTERFACE_NAME, self.log, model_type=selected_model)
                self.sniffer_thread = threading.Thread(target=self.sniffer_service.start)
                self.sniffer_thread.daemon = True
                self.sniffer_thread.start()
                self.btn_sniffer.config(text="STOP SNIFFER", bg="red")
            except Exception as e:
                self.log(f"Failed to load {selected_model} model: {e}\n(Did you train it first?)\n", "red")

    def run_attack_script(self, script_name):
        self.stop_attack() # עצירת התקפות קודמות
        
        # --- חישוב הנתיב המדויק לתיקיית Tests ---
        # 1. איפה אני נמצא עכשיו? (src/Interface)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 2. עלייה למעלה לתיקיית האב (src)
        src_dir = os.path.dirname(current_dir)
        
        # 3. כניסה לתיקיית Tests וחיבור שם הקובץ
        script_path = os.path.join(src_dir, 'Tests', script_name)
        
        # בדיקה שהקובץ אכן קיים לפני שמנסים להריץ
        if not os.path.exists(script_path):
            messagebox.showerror("Error", f"Script not found at:\n{script_path}")
            self.log(f"Error: Could not find {script_path}\n", "red")
            return

        self.log(f"\n🚀 Launching {script_name}...\n", "orange")
        
        try:
            # הרצה בחלון קונסול נפרד
            self.attack_process = subprocess.Popen([sys.executable, script_path], creationflags=0x08000000)
        except Exception as e:
            self.log(f"Error launching attack: {e}\n", "red")

    def stop_attack(self):
        if self.attack_process:
            self.attack_process.terminate()
            self.attack_process = None
            self.log("\n🛑 Attack simulation stopped.\n", "yellow")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IDSDashboard(root)
        root.mainloop()
    except KeyboardInterrupt:
        pass