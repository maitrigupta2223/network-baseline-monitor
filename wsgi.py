"""WSGI entry point for gunicorn / production deployment (Render, etc.).

The engine and simulator are initialised at import time so gunicorn can
simply do:  gunicorn wsgi:app
"""
from monitor.app import create_app
from monitor.config import CONFIG
from monitor.engine import Engine
from monitor.simulator import Simulator

source = Simulator()
engine = Engine(source=source, cfg=CONFIG)
engine.start()

app = create_app(engine, CONFIG)
