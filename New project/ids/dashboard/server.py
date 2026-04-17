from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template

from ids.config import IDSSettings
from ids.core.state import RuntimeState


class DashboardServer:
    """Serve a lightweight dashboard for live packet and alert monitoring."""

    def __init__(self, settings: IDSSettings, state: RuntimeState) -> None:
        self.settings = settings
        self.state = state
        base_dir = Path(__file__).resolve().parent
        self.app = Flask(
            __name__,
            template_folder=str(base_dir / "templates"),
            static_folder=str(base_dir / "static"),
        )
        self._register_routes()

    def _register_routes(self) -> None:
        @self.app.get("/")
        def index() -> str:
            return render_template("dashboard.html", refresh_interval_ms=2000)

        @self.app.get("/api/status")
        def status() -> object:
            return jsonify(self.state.snapshot())

        @self.app.get("/health")
        def health() -> tuple[dict[str, str], int]:
            return {"status": "ok"}, 200

    def run(self) -> None:
        self.app.run(
            host=self.settings.dashboard_host,
            port=self.settings.dashboard_port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )

