# IntrusionSense-IDS

IntrusionSense-IDS is a Network Intrusion Detection System (IDS) that uses machine learning to sniff network traffic and identify potential security threats in real-time. It employs a two-layer detection engine to first filter out normal traffic and then perform deep analysis to categorize specific attacks.

## Features
- **Real-Time Packet Sniffing**: Captures and processes network traffic live from your network interface.
- **2-Stage Machine Learning Pipeline**: 
  - *Layer 1 (Gatekeeper)*: Quickly identifies whether traffic is normal or suspicious.
  - *Layer 2 (Deep Analysis)*: Categorizes the specific type of threat.
- **Web Dashboard**: Live alerts, a 24-hour activity strip, rules, sensors, users and an activity log, with role-based access (Admin, Manager, SOC Analyst).
- **Sensor and server split**: the sensor captures traffic on the machine you watch; the server (and its database) can run anywhere.

## Prerequisites

To run this project, particularly on Windows, you must have the following installed:

1. **Python 3.11+**
   Ensure Python is added to your System PATH during installation.

2. **Npcap (Critical for Windows)**
   The packet sniffing engine (`scapy`) requires a driver to capture raw packets from your network interface. If you encounter a `winpcap` error, it is because Windows does not provide this by default.
   - Download Npcap from [npcap.com](https://npcap.com/).
   - **IMPORTANT:** During the installation, you **MUST** check the box that says: **"Install Npcap in WinPcap API-compatible Mode"**.

## Database Setup

The database runs in Docker, so MySQL is not installed on your computer.

1. Install [Docker](https://docs.docker.com/get-started/get-docker/) (Docker Engine on Linux, Docker Desktop on Windows/macOS).
2. Copy `.env.example` to `.env` in the repo root and set `DB_PASSWORD` to a new strong password. `.env` is gitignored.
3. Start the database (it creates the `intrusionsense` database and user on first start, and keeps its data in a Docker volume):
   ```bash
   docker compose up -d db
   ```
4. Start the server (see below) and open http://127.0.0.1:8000. The first visit asks you to create the admin account; there are no default accounts.

The app uses SQLAlchemy and creates the tables (`Users`, `Rules`, `Alerts`, `TrafficLogs`) on startup.

## Installation

```bash
git clone https://github.com/TonnyGol/IntrusionSense-IDS.git
cd IntrusionSense-IDS
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## How to Run

1. Start the database: `docker compose up -d db`
2. Start the server: `intrusionsense serve` (listens on 127.0.0.1:8000)
3. In the web UI, open **Sensors**, register a sensor and copy its command.
4. Run that command on the machine you want to watch (capture needs root, or `CAP_NET_RAW` on Linux, or Npcap on Windows):

   ```bash
   INTRUSIONSENSE_SENSOR_TOKEN=<token> sudo -E "$(command -v intrusionsense)" sensor --server http://127.0.0.1:8000
   ```

   (`sudo` does not see the virtual environment's PATH, so the full path is passed.)

   To try it without live traffic, replay a capture file: add `--pcap capture.pcap` instead of sniffing.

Run the tests with `pytest`.
