import sys
import os
import json
import asyncio
from typing import List, Dict, Any

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(current_dir)
sys.path.append(src_dir)
sys.path.append(os.path.join(src_dir, 'Interface'))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, FileResponse
from pydantic import BaseModel
import uvicorn

from Interface.sniffer_service import SnifferService
from net_utils import get_active_interface_name
import config

app = FastAPI(title="IntrusionSense SPA Backend")

INTERFACE_NAME = get_active_interface_name()
RULES_FILE = os.path.join(current_dir, 'rules.json')
HIST_LOGS_FILE = os.path.join(current_dir, 'historical_logs.json')

sniffer_service = None
is_sniffing = False
connected_clients: List[WebSocket] = []
alert_cache: List[Dict[Any, Any]] = []

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def sniffer_log_callback(message, details=None):
    loop = asyncio.get_event_loop()
    
    if "ALERT!" in message:
        try:
            parts = message.split("[")
            src_ip = parts[1].split("]")[0]
            dst_ip = parts[2].split("]")[0]
            rest = message.split(" : ")[1]
            attack_type = rest.split(" (")[0]
            confidence = rest.split("(")[1].rstrip(")\n")
            
            alert_data = {
                "type": "alert",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "attack_type": attack_type,
                "confidence": confidence,
                "details": details or {},
                "message": message
            }
            asyncio.run_coroutine_threadsafe(manager.broadcast(alert_data), loop)
        except (IndexError, ValueError):
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message, "level": "warning"}), loop)
    else:
        level = "system" if "Sniffer" in message or "Layer" in message else "info"
        asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "log", "message": message, "level": level}), loop)


class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    valid_users = getattr(config, 'ADMIN_USERS', {})
    if valid_users.get(req.username) == req.password:
        return {"success": True, "message": "Login successful"}
    return {"success": False, "message": "Invalid credentials"}

@app.get("/api/status")
async def get_status():
    packet_count = sniffer_service.packet_count if (sniffer_service and is_sniffing) else 0
    return {
        "is_sniffing": is_sniffing,
        "packet_count": packet_count
    }

@app.post("/api/sniffer/start")
async def start_sniffer():
    global sniffer_service, is_sniffing
    if is_sniffing:
        return {"success": True, "message": "Already sniffing"}
    try:
        sniffer_service = SnifferService(INTERFACE_NAME, sniffer_log_callback)
        import threading
        t = threading.Thread(target=sniffer_service.start)
        t.daemon = True
        t.start()
        is_sniffing = True
        return {"success": True, "message": "Sniffer started"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.post("/api/sniffer/stop")
async def stop_sniffer():
    global sniffer_service, is_sniffing
    if not is_sniffing:
        return {"success": True, "message": "Not sniffing"}
    if sniffer_service:
        sniffer_service.stop()
    is_sniffing = False
    return {"success": True, "message": "Sniffer stopped"}

@app.get("/api/rules")
async def get_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
    return []

@app.post("/api/rules")
async def save_rules(rules: List[dict]):
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=4)
    return {"success": True}

@app.get("/api/historical_logs")
async def get_historical_logs():
    if os.path.exists(HIST_LOGS_FILE):
        with open(HIST_LOGS_FILE, 'r') as f:
            return json.load(f)
    return []

@app.post("/api/historical_logs")
async def add_historical_log(log: Dict[Any, Any]):
    logs = []
    if os.path.exists(HIST_LOGS_FILE):
        with open(HIST_LOGS_FILE, 'r') as f:
            logs = json.load(f)
    logs.append(log)
    with open(HIST_LOGS_FILE, 'w') as f:
        json.dump(logs, f, indent=4)
    return {"success": True}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


static_dir = os.path.join(current_dir, 'static')
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(static_dir, 'index.html'))

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
