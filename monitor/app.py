"""Flask web layer.

Endpoints:
    GET  /                 -> dashboard HTML
    GET  /api/state        -> live KPI/chart data (polled by the dashboard)
    GET  /api/alerts       -> recent alerts (polled / on demand)
    POST /api/control      -> {"action": "stop" | "start" | "reset"}
    GET  /api/health       -> liveness
"""
from __future__ import annotations
import os
from typing import Optional

from flask import Flask, jsonify, render_template, request

from .config import CONFIG, Config
from .engine import Engine


HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)


def create_app(engine: Engine, cfg: Optional[Config] = None) -> Flask:
    cfg = cfg or CONFIG
    app = Flask(
        __name__,
        template_folder=os.path.join(PROJECT_ROOT, "templates"),
        static_folder=os.path.join(PROJECT_ROOT, "static"),
    )

    @app.route("/")
    def index():
        return render_template("dashboard.html", cfg=cfg)

    @app.route("/api/state")
    def api_state():
        return jsonify(engine.state())

    @app.route("/api/alerts")
    def api_alerts():
        limit = int(request.args.get("limit", 100))
        return jsonify({"alerts": engine.recent_alerts(limit=limit)})

    @app.route("/api/control", methods=["POST"])
    def api_control():
        data = request.get_json(silent=True) or {}
        action = (data.get("action") or "").lower()
        if action == "stop":
            engine.stop()
            return jsonify({"ok": True, "state": "stopped"})
        if action == "start":
            engine.start()
            return jsonify({"ok": True, "state": "running"})
        return jsonify({"ok": False, "error": "unknown action"}), 400

    @app.route("/api/health")
    def api_health():
        return jsonify({"ok": True})

    return app
