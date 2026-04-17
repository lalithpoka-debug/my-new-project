from __future__ import annotations

from collections import defaultdict, deque

from ids.config import IDSSettings
from ids.core.models import Alert


class SignatureDetector:
    """Detect well-known packet patterns such as scans and floods."""

    def __init__(self, settings: IDSSettings) -> None:
        self.settings = settings
        self.syn_events: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self.icmp_events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.port_events: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(
            deque
        )

    def analyze(self, packet_info: dict[str, object]) -> list[Alert]:
        alerts: list[Alert] = []
        protocol = str(packet_info["protocol"])
        src_ip = str(packet_info["src_ip"])
        dst_ip = str(packet_info["dst_ip"])
        epoch = float(packet_info["epoch"])

        if protocol == "TCP":
            flags = str(packet_info["tcp_flags"])
            dst_port = int(packet_info["dst_port"] or 0)

            if self._is_syn_only(flags):
                alerts.extend(
                    self._check_syn_flood(packet_info, src_ip, dst_ip, dst_port, epoch)
                )
                alerts.extend(
                    self._check_port_scan(packet_info, src_ip, dst_ip, dst_port, epoch)
                )

            if self._is_null_scan(flags):
                alerts.append(
                    self._create_alert(
                        packet_info,
                        severity="HIGH",
                        rule_id="SIG-NULL-SCAN",
                        category="Suspicious Packet",
                        message="Potential TCP NULL scan detected",
                        details="TCP packet arrived with no active flags set.",
                    )
                )

            if self._is_xmas_scan(flags):
                alerts.append(
                    self._create_alert(
                        packet_info,
                        severity="HIGH",
                        rule_id="SIG-XMAS-SCAN",
                        category="Suspicious Packet",
                        message="Potential TCP Xmas scan detected",
                        details=f"Suspicious TCP flag combination observed: {flags}.",
                    )
                )

        if protocol == "ICMP":
            alerts.extend(self._check_icmp_flood(packet_info, src_ip, dst_ip, epoch))

        if self._is_large_udp_broadcast(packet_info):
            alerts.append(
                self._create_alert(
                    packet_info,
                    severity="MEDIUM",
                    rule_id="SIG-BROADCAST-UDP",
                    category="Suspicious Packet",
                    message="Large UDP packet sent to broadcast address",
                    details=(
                        "Broadcast-style UDP traffic may indicate discovery abuse or "
                        "misuse of internal services."
                    ),
                )
            )

        return alerts

    def _check_syn_flood(
        self,
        packet_info: dict[str, object],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        epoch: float,
    ) -> list[Alert]:
        key = (src_ip, dst_ip, dst_port)
        bucket = self.syn_events[key]
        self._append_time(bucket, epoch, self.settings.syn_flood_window_seconds)

        if len(bucket) < self.settings.syn_flood_threshold:
            return []

        return [
            self._create_alert(
                packet_info,
                severity="CRITICAL",
                rule_id="SIG-SYN-FLOOD",
                category="DoS Attack",
                message="Possible SYN flood detected",
                details=(
                    f"{len(bucket)} TCP SYN packets hit {dst_ip}:{dst_port} within "
                    f"{self.settings.syn_flood_window_seconds} seconds."
                ),
            )
        ]

    def _check_icmp_flood(
        self,
        packet_info: dict[str, object],
        src_ip: str,
        dst_ip: str,
        epoch: float,
    ) -> list[Alert]:
        key = (src_ip, dst_ip)
        bucket = self.icmp_events[key]
        self._append_time(bucket, epoch, self.settings.icmp_flood_window_seconds)

        if len(bucket) < self.settings.icmp_flood_threshold:
            return []

        return [
            self._create_alert(
                packet_info,
                severity="HIGH",
                rule_id="SIG-ICMP-FLOOD",
                category="DoS Attack",
                message="Possible ICMP flood detected",
                details=(
                    f"{len(bucket)} ICMP packets arrived from {src_ip} within "
                    f"{self.settings.icmp_flood_window_seconds} seconds."
                ),
            )
        ]

    def _check_port_scan(
        self,
        packet_info: dict[str, object],
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        epoch: float,
    ) -> list[Alert]:
        key = (src_ip, dst_ip)
        bucket = self.port_events[key]
        bucket.append((epoch, dst_port))
        self._trim_port_bucket(bucket, epoch, self.settings.port_scan_window_seconds)

        unique_ports = {port for _, port in bucket}
        if len(unique_ports) < self.settings.port_scan_unique_ports_threshold:
            return []

        return [
            self._create_alert(
                packet_info,
                severity="HIGH",
                rule_id="SIG-PORT-SCAN",
                category="Port Scan",
                message="Potential TCP port scan detected",
                details=(
                    f"Source {src_ip} targeted {len(unique_ports)} unique destination "
                    f"ports on {dst_ip} in the last "
                    f"{self.settings.port_scan_window_seconds} seconds."
                ),
                include_port=False,
            )
        ]

    def _append_time(self, bucket: deque[float], epoch: float, window_seconds: int) -> None:
        bucket.append(epoch)
        while bucket and epoch - bucket[0] > window_seconds:
            bucket.popleft()

    def _trim_port_bucket(
        self,
        bucket: deque[tuple[float, int]],
        epoch: float,
        window_seconds: int,
    ) -> None:
        while bucket and epoch - bucket[0][0] > window_seconds:
            bucket.popleft()

    def _is_syn_only(self, flags: str) -> bool:
        normalized = flags.upper()
        return "S" in normalized and "A" not in normalized

    def _is_null_scan(self, flags: str) -> bool:
        normalized = flags.strip().upper()
        return normalized in {"", "0"}

    def _is_xmas_scan(self, flags: str) -> bool:
        normalized = set(flags.upper())
        return {"F", "P", "U"}.issubset(normalized)

    def _is_large_udp_broadcast(self, packet_info: dict[str, object]) -> bool:
        protocol = str(packet_info["protocol"])
        dst_ip = str(packet_info["dst_ip"])
        length = int(packet_info["length"])
        return (
            protocol == "UDP"
            and "." in dst_ip
            and dst_ip.endswith(".255")
            and length >= self.settings.anomaly_large_udp_broadcast_threshold
        )

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
