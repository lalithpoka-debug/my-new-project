from __future__ import annotations

import numpy as np
import pandas as pd

from ids.config import IDSSettings
from ids.core.models import Alert
from ids.core.state import RuntimeState


class AnomalyDetector:
    """Detect deviations from recent traffic using simple statistical rules."""

    def __init__(self, settings: IDSSettings, state: RuntimeState) -> None:
        self.settings = settings
        self.state = state

    def analyze(self, packet_info: dict[str, object]) -> list[Alert]:
        recent_packets = self.state.get_recent_packets()
        if len(recent_packets) < self.settings.anomaly_min_packets:
            return []

        frame = pd.DataFrame(recent_packets)
        if frame.empty or "epoch" not in frame:
            return []

        current_epoch = float(packet_info["epoch"])
        window_start = current_epoch - self.settings.anomaly_window_seconds
        window_frame = frame.loc[frame["epoch"] >= window_start].copy()

        if len(window_frame) < self.settings.anomaly_min_packets:
            return []

        alerts: list[Alert] = []
        alerts.extend(self._detect_source_spike(window_frame, packet_info))
        alerts.extend(self._detect_large_packet(window_frame, packet_info))
        alerts.extend(self._detect_wide_targeting(window_frame, packet_info))
        return alerts

    def _detect_source_spike(
        self,
        window_frame: pd.DataFrame,
        packet_info: dict[str, object],
    ) -> list[Alert]:
        src_ip = str(packet_info["src_ip"])
        source_counts = window_frame.groupby("src_ip").size()
        source_packet_count = int(source_counts.get(src_ip, 0))

        if source_packet_count < self.settings.anomaly_high_traffic_threshold:
            return []

        total_window_packets = int(len(window_frame))
        ratio = source_packet_count / total_window_packets
        return [
            self._create_alert(
                packet_info,
                severity="MEDIUM",
                rule_id="ANOM-TRAFFIC-SPIKE",
                category="Anomaly",
                message="Traffic spike from a single source detected",
                details=(
                    f"{src_ip} generated {source_packet_count}/{total_window_packets} "
                    f"packets in the last {self.settings.anomaly_window_seconds} seconds "
                    f"({ratio:.0%} of recent traffic)."
                ),
            )
        ]

    def _detect_large_packet(
        self,
        window_frame: pd.DataFrame,
        packet_info: dict[str, object],
    ) -> list[Alert]:
        lengths = window_frame["length"].astype(float).to_numpy()
        mean_length = float(np.mean(lengths))
        std_length = float(np.std(lengths))
        adaptive_threshold = mean_length + (
            self.settings.anomaly_large_packet_sigma * std_length
        )
        final_threshold = max(
            self.settings.anomaly_large_packet_min_length,
            adaptive_threshold,
        )
        current_length = int(packet_info["length"])

        if current_length < final_threshold:
            return []

        return [
            self._create_alert(
                packet_info,
                severity="MEDIUM",
                rule_id="ANOM-LARGE-PACKET",
                category="Anomaly",
                message="Unusually large packet observed",
                details=(
                    f"Current packet length {current_length} bytes exceeded the recent "
                    f"baseline threshold of {final_threshold:.1f} bytes."
                ),
            )
        ]

    def _detect_wide_targeting(
        self,
        window_frame: pd.DataFrame,
        packet_info: dict[str, object],
    ) -> list[Alert]:
        src_ip = str(packet_info["src_ip"])
        if packet_info["dst_port"] is None:
            return []

        source_frame = window_frame.loc[window_frame["src_ip"] == src_ip]
        port_series = source_frame["dst_port"].dropna()
        unique_ports = int(port_series.nunique())

        if unique_ports < self.settings.anomaly_scanner_port_threshold:
            return []

        return [
            self._create_alert(
                packet_info,
                severity="MEDIUM",
                rule_id="ANOM-WIDE-TARGETING",
                category="Anomaly",
                message="One source is probing many service ports",
                details=(
                    f"{src_ip} contacted {unique_ports} distinct destination ports in "
                    f"the last {self.settings.anomaly_window_seconds} seconds."
                ),
                include_port=False,
            )
        ]

    def _create_alert(
        self,
        packet_info: dict[str, object],
        *,
        severity: str,
        rule_id: str,
        category: str,
        message: str,
        details: str,
        include_port: bool = True,
    ) -> Alert:
        destination = str(packet_info["dst_ip"])
        if include_port and packet_info["dst_port"] is not None:
            destination = f"{destination}:{packet_info['dst_port']}"

        return Alert(
            timestamp=str(packet_info["timestamp"]),
            severity=severity,
            rule_id=rule_id,
            category=category,
            source=str(packet_info["src_ip"]),
            destination=destination,
            message=message,
            details=details,
        )
