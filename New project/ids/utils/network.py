from __future__ import annotations

from scapy.all import get_if_list

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:  # pragma: no cover - only used on non-Windows systems
    get_windows_if_list = None


def list_available_interfaces() -> list[str]:
    if get_windows_if_list is not None:
        interfaces: list[str] = []
        for item in get_windows_if_list():
            name = item.get("name") or item.get("description") or "Unknown"
            interfaces.append(name)
        return interfaces
    return get_if_list()


def print_available_interfaces() -> None:
    print("\nAvailable network interfaces:\n")
    for index, name in enumerate(list_available_interfaces(), start=1):
        print(f"{index}. {name}")
