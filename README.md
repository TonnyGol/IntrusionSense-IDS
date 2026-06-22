# IntrusionSense-IDS

IntrusionSense-IDS is a Network Intrusion Detection System (IDS) that uses machine learning to sniff network traffic and identify potential security threats in real-time. It employs a two-layer detection engine to first filter out normal traffic and then perform deep analysis to categorize specific attacks.

## Features
- **Real-Time Packet Sniffing**: Captures and processes network traffic live from your network interface.
- **2-Stage Machine Learning Pipeline**: 
  - *Layer 1 (Gatekeeper)*: Quickly identifies whether traffic is normal or suspicious.
  - *Layer 2 (Deep Analysis)*: Categorizes the specific type of threat.
- **Interactive Dashboard**: A user-friendly graphical interface to monitor the network.

## Prerequisites

To run this project, particularly on Windows, you must have the following installed:

1. **Python 3.8+**
   Ensure Python is added to your System PATH during installation.

2. **Npcap (Critical for Windows)**
   The packet sniffing engine (`scapy`) requires a driver to capture raw packets from your network interface. If you encounter a `winpcap` error, it is because Windows does not provide this by default.
   - Download Npcap from [npcap.com](https://npcap.com/).
   - **IMPORTANT:** During the installation, you **MUST** check the box that says: **"Install Npcap in WinPcap API-compatible Mode"**.

## Database Setup

This project uses MySQL for storing historical logs, alerts, and user roles. To set it up locally:

1. **Install MySQL Server and MySQL Workbench**:
   - Download the MySQL Installer from [mysql.com](https://dev.mysql.com/downloads/installer/).
   - During installation, choose the "Developer Default" or "Server only" setup. Make sure to install MySQL Workbench as well.

2. **Configure the Database**:
   - Open MySQL Workbench and connect to your local MySQL Server as `root`.
   - The default configuration expects the root password to be `1234` (you can change this in `src/config.py`).
   - Create a new database schema named `intrusionsense`:
     ```sql
     CREATE DATABASE intrusionsense;
     ```
   - The application uses SQLAlchemy and will automatically create the required tables (`Users`, `Rules`, `Alerts`, `TrafficLogs`) on startup.

## Installation

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/YourUsername/IntrusionSense-IDS.git
   cd IntrusionSense-IDS
   ```

2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: This will install packages like `scapy`, `numpy`, `pandas`, `scikit-learn`, `joblib`, etc.*

## How to Run

To launch the IntrusionSense-IDS dashboard and start monitoring:

```bash
cd src/Interface
python dashboard.py
```
