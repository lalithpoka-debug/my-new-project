from __future__ import annotations

from collections import Counter, deque
from threading import Lock
from typing import Any


class RuntimeState:
    def __init__(
        self,
        packet_history_size: int = 4000,
        recent_alert_limit: int = 50,
    ) -> None:
        self._lock = Lock()
        self.total_packets = 0
        self.total_alerts = 0
        self.protocol_counter: Counter[str] = Counter()
        self.source_counter: Counter[str] = Counter()
        self.destination_counter: Counter[str] = Counter()
        self.severity_counter: Counter[str] = Counter()
        self.category_counter: Counter[str] = Counter()
        self.recent_packets: deque[dict[str, Any]] = deque(maxlen=packet_history_size)
        self.recent_alerts: deque[dict[str, str]] = deque(maxlen=recent_alert_limit)

    def record_packet(self, packet_info: dict[str, Any]) -> None:
        with self._lock:
            self.total_packets += 1
            self.protocol_counter[packet_info["protocol"]] += 1
            self.source_counter[packet_info["src_ip"]] += 1
            self.destination_counter[packet_info["dst_ip"]] += 1
            self.recent_packets.append(packet_info)

    def record_alert(self, alert: dict[str, str]) -> None:
        with self._lock:
            self.total_alerts += 1
            self.severity_counter[alert["severity"]] += 1
            self.category_counter[alert["category"]] += 1
            self.recent_alerts.appendleft(alert)

    def get_recent_packets(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.recent_packets)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            recent_packets = list(self.recent_packets)
            total_packets = self.total_packets
            total_alerts = self.total_alerts
            protocol_counter = dict(self.protocol_counter)
            top_sources = self.source_counter.most_common(5)
            top_destinations = self.destination_counter.most_common(5)
            severity_counter = dict(self.severity_counter)
            category_counter = dict(self.category_counter)
            recent_alerts = list(self.recent_alerts)

        latest_time = recent_packets[-1]["timestamp"] if recent_packets else "No traffic yet"
        now_epoch = recent_packets[-1]["epoch"] if recent_packets else 0.0
        packets_last_10s = 0
        if recent_packets:
            packets_last_10s = sum(
                1 for packet in recent_packets if now_epoch - packet["epoch"] <= 10
            )

        return {
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "protocols": protocol_counter,
            "severities": severity_counter,
            "categories": category_counter,
            "top_sources": [
                {"ip": ip, "count": count} for ip, count in top_sources
            ],
            "top_destinations": [
                {"ip": ip, "count": count} for ip, count in top_destinations
            ],
            "recent_alerts": recent_alerts,
            "recent_packets": list(reversed(recent_packets[-12:])),
            "packets_last_10s": packets_last_10s,
            "last_packet_time": latest_time,
        }
