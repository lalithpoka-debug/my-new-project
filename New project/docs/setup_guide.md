# Setup Guide

## System Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- Administrator access for live packet capture
- Npcap installed on the system

## Installation Steps

### 1. Open the Project Folder

```powershell
cd "C:\Users\lalitheswar\OneDrive\Documents\New project"
```

### 2. Create and Activate a Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Upgrade pip and Install the Required Libraries

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Install Npcap

Install Npcap and enable `Install Npcap in WinPcap API-compatible Mode`.

### 5. Check Available Interfaces

```powershell
python run_ids.py --list-interfaces
```

### 6. Test the Project in Demo Mode

```powershell
python run_ids.py --demo
```

What happens:

- Synthetic normal and malicious packets are generated automatically.
- Alerts appear in the console.
- The dashboard starts on `http://127.0.0.1:5000`.
- Logs are written to `logs\ids_alerts.log`.

### 7. Run the IDS on Real Traffic

Open PowerShell as Administrator and run:

```powershell
python run_ids.py --iface "Wi-Fi"
```

To also see every live packet in the terminal:

```powershell
python run_ids.py --iface "Wi-Fi" --show-packets
```

### 8. Analyze a PCAP File

```powershell
python run_ids.py --pcap sample_data\traffic_capture.pcap
```

## Watch the Backend Packet Flow

If you want to observe the backend processing path in the terminal, enable packet tracing:

```powershell
python run_ids.py --demo --show-packets
```

This will print lines like:

```text
[2026-04-11 10:20:00] [PACKET] TCP | 192.168.1.10:51080 -> 8.8.8.8:80 | len=40 payload=0 ttl=64 flags=PA
```

## Common Problems and Fixes

### Problem: `Permission denied`

Run PowerShell as Administrator.

### Problem: `No module named scapy`

Activate the virtual environment and run `python -m pip install -r requirements.txt`.

### Problem: Live capture starts but no packets are shown

Check the selected interface and generate some network traffic.

### Problem: Browser page is blank

Verify that Flask started successfully and open `http://127.0.0.1:5000`.

## Recommended Demo Flow

1. Start the IDS in demo mode.
2. Show the live dashboard.
3. Explain packet counts and protocols.
4. Point out alerts for port scan, SYN flood, and ICMP flood.
5. Show the alert log file.
6. Explain how signature and anomaly detection work together.
