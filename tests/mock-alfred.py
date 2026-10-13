#!/usr/bin/env python3
"""Minimal stand-in for the Alfred agent API, used by the install smoke tests.

It enforces the same contract the agent relies on: a bearer agent key, a
non-placeholder hardware UUID, a non-decreasing activation nonce, and a
registration lookup that only succeeds after enrollment. Requests are appended
to the log file given as the second argument so tests can assert on them.
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(sys.argv[1])
LOG = sys.argv[2]
KEY = sys.argv[3]
UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
devices = {}


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        if self.headers.get("Authorization") == f"Bearer {KEY}":
            return True
        self.reply(401, {"error": "invalid_key"})
        return False

    def record(self, body):
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"method": self.command, "path": self.path, "body": body}) + "\n")

    def do_GET(self):
        url = urlparse(self.path)
        self.record(None)
        if not self.authorized():
            return
        if url.path != "/v1/agent/registration":
            return self.reply(404, {"error": "not_found"})
        uuid = (parse_qs(url.query).get("hardware_uuid") or [""])[0].upper()
        self.reply(200, {"registered": uuid in devices})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "invalid_json"})
        self.record(body)
        if not self.authorized():
            return
        uuid = str(body.get("hardwareUuid", "")).upper()
        if not UUID.match(uuid) or len(set(uuid.replace("-", ""))) == 1:
            return self.reply(422, {"error": "invalid_hardware_uuid"})
        if self.path == "/v1/agent/enroll":
            nonce = body.get("activationNonce")
            if nonce is not None and nonce < devices.get(uuid, 0):
                return self.reply(409, {"error": "stale_activation_nonce"})
            devices[uuid] = nonce or devices.get(uuid, 0)
            return self.reply(201, {"deviceId": "dev_smoke"})
        if uuid not in devices:
            return self.reply(404, {"error": "device_not_enrolled"})
        if self.path in ("/v1/agent/checkin", "/v1/agent/ai-inventory"):
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "not_found"})

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
