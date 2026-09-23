#!/usr/bin/env python3
import argparse
import importlib.util
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone

from flask import request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APP = os.path.join(BASE_DIR, "..", "Vulnerable", "vulnerable_app.py")
DEFAULT_LOG = os.path.join(BASE_DIR, "logs", "wcp_forensic.log")

CACHE_PATTERN = re.compile(r"Cache:\s*(HIT|MISS)", re.I)
LINK_PATTERN = re.compile(r"https?://([^/'\"\s<>]+)/reset", re.I)


def load_app(path):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        sys.exit(f"Error: app file not found: {path}")
    sys.path.insert(0, os.path.dirname(path))
    spec = importlib.util.spec_from_file_location("wcp_target_app", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "app"):
        sys.exit(f"Error: {path} does not expose a Flask 'app' instance")
    return module.app


def instrument(app, log_path):
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    lock = threading.Lock()

    @app.after_request
    def log_request(resp):
        try:
            body = "" if resp.direct_passthrough else resp.get_data(as_text=True)
            cache_match = CACHE_PATTERN.search(body)
            link_match = LINK_PATTERN.search(body)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "client": request.remote_addr,
                "method": request.method,
                "path": request.path,
                "query": request.query_string.decode("latin-1"),
                "host": request.host,
                "x_forwarded_host": request.headers.get("X-Forwarded-Host"),
                "user_agent": request.headers.get("User-Agent"),
                "status": resp.status_code,
                "cache_status": cache_match.group(1).upper() if cache_match else None,
                "served_host": link_match.group(1) if link_match else None,
            }
            with lock, open(log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception as exc:
            print(f"Logging error: {exc}", file=sys.stderr)
        return resp


def main():
    parser = argparse.ArgumentParser(description="Run application with forensic request logging")
    parser.add_argument("--app", default=DEFAULT_APP, help="Path to Flask application")
    parser.add_argument("--log", default=DEFAULT_LOG, help="Output forensic log path")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--fresh", action="store_true", help="Truncate existing log file")
    args = parser.parse_args()

    if args.fresh:
        os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
        open(args.log, "w", encoding="utf-8").close()

    app = load_app(args.app)
    instrument(app, args.log)
    print(f"Target app : {os.path.abspath(args.app)}")
    print(f"Forensic log: {os.path.abspath(args.log)}")
    print(f"Running on  : http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()