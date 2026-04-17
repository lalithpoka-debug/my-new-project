from __future__ import annotations

from collections.abc import Callable
import time
from typing import Any

from scapy.all import ICMP, IP, Raw, TCP, UDP


class DemoTrafficGenerator:
    def __init__(self, packet_callback: Callable[[Any], None]) -> None:
        self.packet_callback = packet_callback

    def start(self) -> None:
        print("Starting demo mode. Synthetic packets will be generated every second.")
        while True:
            self._generate_normal_traffic()
            self._generate_port_scan()
            self._generate_syn_flood()
            self._generate_icmp_burst()
            self._generate_large_udp_packet()
            time.sleep(2)

    def _generate_normal_traffic(self) -> None:
        for port in (80, 443, 53):
            packet = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(
                sport=51000 + port,
                dport=port,
                flags="PA",
            )
            self.packet_callback(packet)

    def _generate_port_scan(self) -> None:
        for port in range(20, 36):
            packet = IP(src="10.10.10.50", dst="192.168.1.1") / TCP(
                sport=41000,
                dport=port,
                flags="S",
            )
            self.packet_callback(packet)
            time.sleep(0.02)

    def _generate_syn_flood(self) -> None:
        for port in range(1000, 1040):
            packet = IP(src="172.16.0.25", dst="192.168.1.100") / TCP(
                sport=40000 + port,
                dport=80,
                flags="S",
            )
            self.packet_callback(packet)

    def _generate_icmp_burst(self) -> None:
        for _ in range(25):
            packet = IP(src="192.168.56.77", dst="192.168.1.1") / ICMP()
            self.packet_callback(packet)

    def _generate_large_udp_packet(self) -> None:
        payload = "X" * 1200
        packet = IP(src="192.168.1.60", dst="192.168.1.255") / UDP(
            sport=53000,
            dport=161,
        ) / Raw(load=payload)
        self.packet_callback(packet)
