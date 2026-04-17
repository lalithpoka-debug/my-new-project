# PPT Content for Presentation

## Slide 1: Title Slide

- Project Title: Real-Time Network Intrusion Detection System
- Name
- Roll Number
- Department / College
- Guide Name

## Slide 2: Introduction

- Network attacks are increasing in modern systems.
- Organizations need tools to monitor suspicious traffic.
- An Intrusion Detection System helps identify attacks in real time.

## Slide 3: Problem Statement

- Manual monitoring of network packets is difficult.
- Small organizations and students need a low-cost IDS solution.
- The goal is to detect suspicious traffic such as DoS and port scanning in real time.

## Slide 4: Objectives

- Capture live network packets.
- Analyze traffic continuously.
- Detect known attacks and anomalies.
- Generate alerts and logs.
- Display results on a dashboard.

## Slide 5: Technology Stack

- Python
- Scapy
- Pandas
- NumPy
- Flask
- Npcap
- Windows OS

## Slide 6: System Architecture

- Packet Capture Layer
- Packet Parsing Layer
- Detection Engine
- Logging Module
- Dashboard Module

## Slide 7: Detection Methodology

### Signature-Based Rules

- SYN flood detection
- ICMP flood detection
- Port scan detection
- NULL and Xmas scan detection

### Anomaly-Based Rules

- traffic spike detection
- unusual packet size detection
- wide port targeting detection

## Slide 8: Project Flow

1. Capture packet
2. Extract fields
3. Store packet data
4. Run signature rules
5. Run anomaly checks
6. Generate alert if suspicious
7. Update logs and dashboard

## Slide 9: Dashboard and Output

- Live packet statistics
- Alert list
- Protocol distribution
- Top source and destination IPs
- Packet history table

## Slide 10: Results

- The IDS successfully detects SYN flood, ICMP flood, TCP port scan, suspicious TCP packets, and abnormal packet behavior.
- Alerts are visible in real time.
- Log file stores evidence of detection.

## Slide 11: Advantages

- Real-time monitoring
- Easy to understand and explain
- Beginner-friendly design
- Useful for cyber security mini projects
- Supports demo mode and PCAP analysis

## Slide 12: Limitations

- Simple thresholds may create false positives.
- No automatic blocking of attacks.
- Does not yet use machine learning.
- Not designed for enterprise-scale traffic.

## Slide 13: Future Scope

- Add machine learning with NSL-KDD
- Add email alerts
- Add database storage
- Add more signatures
- Convert IDS into IPS with blocking

## Slide 14: Conclusion

- The project demonstrates a practical real-time IDS.
- It combines packet capture, rule-based detection, anomaly detection, logging, and dashboard monitoring.
- It is suitable for academic demonstration and further improvement.

## Slide 15: Thank You

- Thank you
- Questions and answers

