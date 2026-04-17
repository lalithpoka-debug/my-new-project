from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scapy.all import sniff

from ids.config import IDSSettings


class PacketSniffer:
    def __init__(
        self,
        settings: IDSSettings,
        packet_callback: Callable[[Any], None],
    ) -> None:
        self.settings = settings
        self.packet_callback = packet_callback

    def start(self) -> None:
        try:
            if self.settings.pcap_file:
                print(f"Reading packets from PCAP: {self.settings.pcap_file}")
                sniff(
                    offline=self.settings.pcap_file,
                    store=False,
                    prn=self.packet_callback,
                )
            else:
                print("Starting live packet capture. Press Ctrl+C to stop.")
                sniff(
                    iface=self.settings.interface,
                    store=False,
                    prn=self.packet_callback,
                )
        except PermissionError:
            print("Permission denied. Run the terminal as Administrator for live capture.")
        except OSError as exc:
            print(f"Packet capture error: {exc}")
