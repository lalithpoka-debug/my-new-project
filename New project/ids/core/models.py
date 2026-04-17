from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class Alert:
    timestamp: str
    severity: str
    rule_id: str
    category: str
    source: str
    destination: str
    message: str
    details: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
