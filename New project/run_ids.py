from __future__ import annotations

import argparse
import threading
from pathlib import Path

from ids.capture.demo_generator import DemoTrafficGenerator
from ids.capture.sniffer import PacketSniffer
from ids.config import IDSSettings
from ids.core.state import RuntimeState
from ids.dashboard.server import DashboardServer
from ids.detection.engine import DetectionEngine
from ids.storage.event_logger import EventLogger
from ids.utils.network import print_available_interfaces


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Real-Time Network Intrusion Detection System (IDS)"
    )
    parser.add_argument(
        "--iface",
        help="Npcap interface name for live packet capture on Windows.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        help="Dashboard host address. Default: 127.0.0.1",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=5000,
        help="Dashboard port number. Default: 5000",
    )
    parser.add_argument(
        "--disable-dashboard",
        action="store_true",
        help="Run IDS without the web dashboard.",
    )
    parser.add_argument(
        "--pcap",
        help="Analyze packets from a PCAP file instead of live capture.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a built-in demo traffic generator for presentations or testing.",
    )
    parser.add_argument(
        "--show-packets",
        action="store_true",
        help="Print every parsed packet in the terminal to trace backend processing live.",
    )
    return parser


def create_settings(args: argparse.Namespace) -> IDSSettings:
    return IDSSettings(
        interface=args.iface,
        dashboard_host=args.dashboard_host,
        dashboard_port=args.dashboard_port,
        dashboard_enabled=not args.disable_dashboard,
        pcap_file=args.pcap,
        demo_mode=args.demo,
        show_packets=args.show_packets,
        project_root=Path.cwd(),
    )


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        print_available_interfaces()
        return

    settings = create_settings(args)
    state = RuntimeState(
        packet_history_size=settings.packet_history_size,
        recent_alert_limit=settings.recent_alert_limit,
    )
    logger = EventLogger(settings.log_file)
    engine = DetectionEngine(settings=settings, state=state, logger=logger)

    print("\n=== Real-Time Network IDS ===")
    print(f"Log file        : {settings.log_file}")
    print(f"Dashboard       : {'enabled' if settings.dashboard_enabled else 'disabled'}")
    print(f"Mode            : {'demo' if settings.demo_mode else 'pcap' if settings.pcap_file else 'live'}")
    print(f"Packet Trace    : {'enabled' if settings.show_packets else 'disabled'}")
    if settings.interface:
        print(f"Interface       : {settings.interface}")
    if settings.dashboard_enabled:
        print(
            f"Dashboard URL   : http://{settings.dashboard_host}:{settings.dashboard_port}"
        )

    if settings.demo_mode:
        source = DemoTrafficGenerator(engine.process_packet)
        worker = threading.Thread(target=source.start, daemon=True)
    else:
        source = PacketSniffer(settings, engine.process_packet)
        worker = threading.Thread(target=source.start, daemon=True)

    worker.start()

    if settings.dashboard_enabled:
        dashboard = DashboardServer(settings=settings, state=state)
        dashboard.run()
    else:
        worker.join()


if __name__ == "__main__":
    main()
