# Real-Time Network Intrusion Detection System

A beginner-friendly but presentation-ready Network Intrusion Detection System (IDS) built in Python for Windows. The project captures packets in real time using Scapy and Npcap, analyzes them with signature-based and anomaly-based logic, raises alerts in the console and log file, and shows live statistics on a simple Flask dashboard.

## Project Objectives

- Capture live packets from the network.
- Detect malicious behavior such as DoS attacks, port scanning, and suspicious packets.
- Combine signature-based detection with anomaly-based detection.
- Generate alerts in the terminal and in log files.
- Provide a simple dashboard for monitoring packets and alerts.

## Key Features

- Live packet capture with Scapy and Npcap
- Offline PCAP analysis mode
- Demo mode for classroom presentations without real attack traffic
- Signature-based detection for SYN flood, ICMP flood, TCP port scan, NULL scan, Xmas scan, and large UDP broadcast packets
- Anomaly-based detection for traffic spikes, unusually large packets, and wide port targeting
- Console alerts and file logging
- Flask dashboard with live refresh

## Folder Structure

```text
New project/
|-- ids/
|   |-- capture/
|   |-- core/
|   |-- dashboard/
|   |   |-- static/
|   |   `-- templates/
|   |-- detection/
|   |-- storage/
|   |-- utils/
|   |-- config.py
|   `-- __init__.py
|-- docs/
|   |-- future_improvements.md
|   |-- module_explanation.md
|   |-- sample_output.md
|   |-- setup_guide.md
|   |-- viva_questions.md
|   `-- presentation/
|       `-- ppt_content.md
|-- logs/
|   `-- .gitkeep
|-- sample_data/
|   `-- README.md
|-- requirements.txt
`-- run_ids.py
```

## Technologies Used

- Python
- Scapy
- Pandas
- NumPy
- Flask
- Npcap
- Windows OS

## Detection Logic

### Signature-Based Detection

- `SIG-SYN-FLOOD`
- `SIG-ICMP-FLOOD`
- `SIG-PORT-SCAN`
- `SIG-NULL-SCAN`
- `SIG-XMAS-SCAN`
- `SIG-BROADCAST-UDP`

### Anomaly-Based Detection

- `ANOM-TRAFFIC-SPIKE`
- `ANOM-LARGE-PACKET`
- `ANOM-WIDE-TARGETING`

## Step-by-Step Setup

Detailed instructions are available in [docs/setup_guide.md](docs/setup_guide.md).

### 1. Install Python

Install Python 3.10 or newer and make sure `python` works in PowerShell.

### 2. Install Npcap

Install Npcap and enable **WinPcap API-compatible mode** during setup.

### 3. Create a Virtual Environment

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 4. Install Dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 5. Run Demo Mode

```powershell
python run_ids.py --demo
```

Open `http://127.0.0.1:5000` in your browser.

### 6. Run Live Capture Mode

```powershell
python run_ids.py --list-interfaces
python run_ids.py --iface "Wi-Fi"
```

### 7. Run PCAP Analysis Mode

```powershell
python run_ids.py --pcap sample_data\traffic_capture.pcap
```

## Example Commands

```powershell
python run_ids.py --demo
python run_ids.py --demo --show-packets
python run_ids.py --disable-dashboard --demo
python run_ids.py --iface "Ethernet"
python run_ids.py --iface "Wi-Fi" --show-packets
python run_ids.py --pcap sample_data\test_traffic.pcap --disable-dashboard
```

## See Live Backend Packet Flow

If you want to watch every parsed packet moving through the backend in the terminal, use:

```powershell
python run_ids.py --iface "Wi-Fi" --show-packets
```

For demo mode:

```powershell
python run_ids.py --demo --show-packets
```

This prints a live packet trace with protocol, source, destination, packet length, payload size, TTL, and TCP flags.

## Documentation Bundle

- Setup guide: [docs/setup_guide.md](docs/setup_guide.md)
- Module explanation: [docs/module_explanation.md](docs/module_explanation.md)
- Sample output: [docs/sample_output.md](docs/sample_output.md)
- PPT content: [docs/presentation/ppt_content.md](docs/presentation/ppt_content.md)
- Viva questions: [docs/viva_questions.md](docs/viva_questions.md)
- Future improvements: [docs/future_improvements.md](docs/future_improvements.md)

## Notes for Submission

- Use `--demo` mode during evaluation if live packet capture is not available.
- Add screenshots of the dashboard and log file to your report.
- Mention clearly that the project uses both signature-based and anomaly-based detection.
- As a future enhancement, you can add a machine learning module using NSL-KDD.
