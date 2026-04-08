#!/usr/bin/env python3
"""
Mock server that logs suspicious connection attempts from npm/pip postinstall hooks.
Listens on localhost:9999 for beacon/reporting connections.
"""
import json
import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path

LOG_FILE = "/tmp/hazmat/beacon_log.json"

# Ensure log directory exists
Path("/tmp/hazmat").mkdir(parents=True, exist_ok=True)


class BeaconHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        try:
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {"raw": body.decode('utf-8', errors='ignore')}

        beacon_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_address[0],
            "path": self.path,
            "payload": data
        }

        # Append to log file
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(beacon_record) + '\n')
        except Exception as e:
            print(f"Error writing log: {e}", file=sys.stderr)

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode('utf-8'))

    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass


def signal_handler(sig, frame):
    print("\n[MOCK SERVER] Shutting down.", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    # Clear log on startup
    try:
        Path(LOG_FILE).unlink(missing_ok=True)
    except Exception as e:
        print(f"Could not clear beacon log: {e}", file=sys.stderr)

    signal.signal(signal.SIGINT, signal_handler)
    server = HTTPServer(("localhost", 9999), BeaconHandler)
    print("[MOCK SERVER] Listening on localhost:9999 for malicious beacons...", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        signal_handler(None, None)
