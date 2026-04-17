from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class IDSSettings:
    interface: str | None = None
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 5000
    dashboard_enabled: bool = True
    pcap_file: str | None = None
    demo_mode: bool = False
    show_packets: bool = False
    project_root: Path = field(default_factory=Path.cwd)

    packet_history_size: int = 4000
    recent_alert_limit: int = 50
    alert_cooldown_seconds: int = 8

    syn_flood_window_seconds: int = 10
    syn_flood_threshold: int = 35
    icmp_flood_window_seconds: int = 5
    icmp_flood_threshold: int = 20
    port_scan_window_seconds: int = 10
    port_scan_unique_ports_threshold: int = 12

    anomaly_window_seconds: int = 20
    anomaly_min_packets: int = 25
    anomaly_high_traffic_threshold: int = 40
    anomaly_scanner_port_threshold: int = 15
    anomaly_large_packet_sigma: float = 2.7
    anomaly_large_packet_min_length: int = 900
    anomaly_large_udp_broadcast_threshold: int = 1000

    @property
    def log_file(self) -> Path:
        return self.project_root / "logs" / "ids_alerts.log"
