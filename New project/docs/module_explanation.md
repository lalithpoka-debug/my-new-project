# Module Explanation

## `run_ids.py`

Main entry point that reads command-line options, builds settings, starts packet capture, launches the detection engine, and optionally starts the dashboard.

## `ids/config.py`

Stores configurable thresholds and runtime options such as dashboard host and port, alert cooldown, packet history size, and detection thresholds.

## `ids/capture/sniffer.py`

Captures packets either from a live interface or from a PCAP file and forwards them to the packet callback.

## `ids/capture/demo_generator.py`

Generates normal traffic and attack-like traffic for classroom demos and testing.

## `ids/capture/packet_parser.py`

Extracts source IP, destination IP, protocol, ports, packet length, payload size, TTL, and TCP flags from every packet.

## `ids/core/models.py`

Defines the `Alert` data structure used by the project.

## `ids/core/state.py`

Stores runtime packet counts, alert counts, top talkers, recent packets, and recent alerts for the dashboard.

## `ids/detection/engine.py`

Runs the full pipeline:

1. Parse the packet
2. Save packet info in runtime state
3. Optionally print a packet trace in the terminal when `--show-packets` is enabled
4. Run signature-based rules
5. Run anomaly-based checks
6. Suppress duplicate alerts using cooldown
7. Print and log alerts

## `ids/detection/signature.py`

Contains known attack-pattern rules for SYN flood, ICMP flood, port scan, NULL scan, Xmas scan, and large UDP broadcast traffic.

## `ids/detection/anomaly.py`

Uses Pandas and NumPy on recent packet history to detect traffic spikes, unusually large packets, and wide port targeting.

## `ids/storage/event_logger.py`

Writes alerts to `logs/ids_alerts.log`.

## `ids/dashboard/server.py`

Runs the Flask web server and exposes the dashboard and JSON API.

## `ids/dashboard/templates/dashboard.html`

Builds the dashboard layout and tables.

## `ids/dashboard/static/dashboard.css`

Styles the dashboard with a responsive card-and-table layout.

## `ids/dashboard/static/dashboard.js`

Refreshes the dashboard automatically by calling the Flask API.

## `ids/utils/network.py`

Lists network interfaces so the user can choose the correct Windows adapter for live capture.
