from __future__ import annotations

from typing import Any

from ids.capture.packet_parser import parse_packet
from ids.config import IDSSettings
from ids.core.models import Alert
from ids.core.state import RuntimeState
from ids.detection.anomaly import AnomalyDetector
from ids.detection.signature import SignatureDetector
from ids.storage.event_logger import EventLogger


class DetectionEngine:
    """Parse packets, run detectors, and publish alerts."""

    def __init__(
        self,
        settings: IDSSettings,
        state: RuntimeState,
        logger: EventLogger,
    ) -> None:
        self.settings = settings
        self.state = state
        self.logger = logger
        self.signature_detector = SignatureDetector(settings)
        self.anomaly_detector = AnomalyDetector(settings, state)
        self._cooldown_cache: dict[tuple[str, str, str], float] = {}

    def process_packet(self, packet: Any) -> None:
        packet_info = parse_packet(packet)
        self.state.record_packet(packet_info)
        if self.settings.show_packets:
            print(self._format_packet_trace(packet_info))

        alerts = []
        alerts.extend(self.signature_detector.analyze(packet_info))
        alerts.extend(self.anomaly_detector.analyze(packet_info))

        for alert in alerts:
            if self._should_emit(alert, float(packet_info["epoch"])):
                self._emit(alert)

    def _should_emit(self, alert: Alert, epoch: float) -> bool:
        key = (alert.rule_id, alert.source, alert.destination)
        last_epoch = self._cooldown_cache.get(key)
        if last_epoch is not None and epoch - last_epoch < self.settings.alert_cooldown_seconds:
            return False

        # Keep the cooldown cache compact during longer monitoring sessions.
        self._cooldown_cache = {
            cache_key: cache_epoch
            for cache_key, cache_epoch in self._cooldown_cache.items()
            if epoch - cache_epoch <= self.settings.alert_cooldown_seconds
        }
        self._cooldown_cache[key] = epoch
        return True

    def _emit(self, alert: Alert) -> None:
        alert_payload = alert.to_dict()
        self.state.record_alert(alert_payload)
        self.logger.log_alert(alert)
        print(self._format_console_alert(alert))

    def _format_console_alert(self, alert: Alert) -> str:
        return (
            f"[{alert.timestamp}] [{alert.severity}] {alert.rule_id} | "
            f"{alert.message} | {alert.source} -> {alert.destination} | {alert.details}"
        )

    def _format_packet_trace(self, packet_info: dict[str, object]) -> str:
        src = str(packet_info["src_ip"])
        dst = str(packet_info["dst_ip"])
        if packet_info["src_port"] is not None:
            src = f"{src}:{packet_info['src_port']}"
        if packet_info["dst_port"] is not None:
            dst = f"{dst}:{packet_info['dst_port']}"

        flags = str(packet_info["tcp_flags"]) or "-"
        ttl = packet_info["ttl"] if packet_info["ttl"] is not None else "-"
        return (
            f"[{packet_info['timestamp']}] [PACKET] "
            f"{packet_info['protocol']} | {src} -> {dst} | "
            f"len={packet_info['length']} payload={packet_info['payload_size']} "
            f"ttl={ttl} flags={flags}"
        )
