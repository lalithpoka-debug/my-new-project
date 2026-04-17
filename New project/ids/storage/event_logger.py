from __future__ import annotations

import logging
from pathlib import Path

from ids.core.models import Alert


class EventLogger:
    SEVERITY_LEVELS = {
        "LOW": logging.INFO,
        "MEDIUM": logging.WARNING,
        "HIGH": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    def __init__(self, log_file: Path) -> None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("ids-alerts")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_alert(self, alert: Alert) -> None:
        text = (
            f"{alert.rule_id} | {alert.source} -> {alert.destination} | "
            f"{alert.message} | {alert.details}"
        )
        level = self.SEVERITY_LEVELS.get(alert.severity.upper(), logging.INFO)
        self.logger.log(level, text)
