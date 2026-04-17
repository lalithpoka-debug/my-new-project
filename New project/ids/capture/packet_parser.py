from __future__ import annotations

from datetime import datetime
import time
from typing import Any

from scapy.all import ICMP, IP, IPv6, Raw, TCP, UDP


def parse_packet(packet: Any) -> dict[str, Any]:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    epoch = time.time()

    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    src_ip = ip_layer.src if ip_layer else "Unknown"
    dst_ip = ip_layer.dst if ip_layer else "Unknown"
    protocol = "OTHER"
    src_port = None
    dst_port = None
    tcp_flags = ""
    ttl = getattr(ip_layer, "ttl", None)

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(IPv6):
        protocol = "IPv6"

    payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

    return {
        "timestamp": now,
        "epoch": epoch,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": len(packet),
        "payload_size": payload_size,
        "ttl": ttl,
        "tcp_flags": tcp_flags,
    }
