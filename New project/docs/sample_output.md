# Sample Output

## Sample Console Output

```text
=== Real-Time Network IDS ===
Log file        : C:\Users\lalitheswar\OneDrive\Documents\New project\logs\ids_alerts.log
Dashboard       : enabled
Mode            : demo
Dashboard URL   : http://127.0.0.1:5000
Starting demo mode. Synthetic packets will be generated every second.
[2026-04-10 15:25:02] [HIGH] SIG-PORT-SCAN | Potential TCP port scan detected | 10.10.10.50 -> 192.168.1.1 | Source 10.10.10.50 targeted 12 unique destination ports on 192.168.1.1 in the last 10 seconds.
[2026-04-10 15:25:02] [CRITICAL] SIG-SYN-FLOOD | Possible SYN flood detected | 172.16.0.25 -> 192.168.1.100:80 | 35 TCP SYN packets hit 192.168.1.100:80 within 10 seconds.
[2026-04-10 15:25:02] [MEDIUM] ANOM-TRAFFIC-SPIKE | Traffic spike from a single source detected | 172.16.0.25 -> 192.168.1.100:80 | 172.16.0.25 generated 40/59 packets in the last 20 seconds (68% of recent traffic).
[2026-04-10 15:25:03] [HIGH] SIG-ICMP-FLOOD | Possible ICMP flood detected | 192.168.56.77 -> 192.168.1.1 | 20 ICMP packets arrived from 192.168.56.77 within 5 seconds.
[2026-04-10 15:25:03] [MEDIUM] SIG-BROADCAST-UDP | Large UDP packet sent to broadcast address | 192.168.1.60 -> 192.168.1.255:161 | Broadcast-style UDP traffic may indicate discovery abuse or misuse of internal services.
[2026-04-10 15:25:03] [MEDIUM] ANOM-LARGE-PACKET | Unusually large packet observed | 192.168.1.60 -> 192.168.1.255:161 | Current packet length 1228 bytes exceeded the recent baseline threshold of 900.0 bytes.
```

## Sample Log File Entries

File: `logs\ids_alerts.log`

```text
[2026-04-10 15:25:02] [ERROR] SIG-PORT-SCAN | 10.10.10.50 -> 192.168.1.1 | Potential TCP port scan detected | Source 10.10.10.50 targeted 12 unique destination ports on 192.168.1.1 in the last 10 seconds.
[2026-04-10 15:25:02] [CRITICAL] SIG-SYN-FLOOD | 172.16.0.25 -> 192.168.1.100:80 | Possible SYN flood detected | 35 TCP SYN packets hit 192.168.1.100:80 within 10 seconds.
[2026-04-10 15:25:02] [WARNING] ANOM-TRAFFIC-SPIKE | 172.16.0.25 -> 192.168.1.100:80 | Traffic spike from a single source detected | 172.16.0.25 generated 40/59 packets in the last 20 seconds (68% of recent traffic).
[2026-04-10 15:25:03] [ERROR] SIG-ICMP-FLOOD | 192.168.56.77 -> 192.168.1.1 | Possible ICMP flood detected | 20 ICMP packets arrived from 192.168.56.77 within 5 seconds.
```

## Dashboard View

When the dashboard is running, the following live information is shown:

- total packets captured
- packets received in the last 10 seconds
- total alerts generated
- last packet timestamp
- protocol distribution
- severity distribution
- top source IPs
- top destination IPs
- recent alerts
- recent packets
