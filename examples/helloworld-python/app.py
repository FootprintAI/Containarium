#!/usr/bin/env python3
"""Tiny hello-world server: shows visitor IP, commit ID, current time.

Also demonstrates the two-line containarium-telemetry init: any OTel
metric the app emits (e.g. the helloworld.requests counter below)
flows through the LXC's otel-sidecar / central collector to the
platform's VictoriaMetrics. Fail-open: if monitoring isn't enabled
on this LXC, init() is a no-op and the app still serves traffic.
"""
import atexit
import datetime
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import containarium_telemetry
from opentelemetry import metrics

# Two-line distro init — env discovery + MeterProvider wiring. Returns
# a Shutdown handle; atexit ensures we flush on clean exit.
_telemetry = containarium_telemetry.init(instrumentations="off")
atexit.register(lambda: _telemetry.shutdown(timeout_s=5.0))

# stdlib http.server has no auto-instrumentor — emit a counter
# manually so the dashboard has something to chart. Any other OTel
# Counter / Histogram / UpDownCounter the app creates works the same.
_meter = metrics.get_meter("helloworld")
_request_counter = _meter.create_counter(
    "helloworld.requests",
    description="Total HTTP requests served",
)

COMMIT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commit.txt')
try:
    with open(COMMIT_FILE) as f:
        COMMIT_ID = f.read().strip()
except FileNotFoundError:
    COMMIT_ID = 'unknown'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        _request_counter.add(1, {"http.method": "GET"})

        forwarded = self.headers.get('X-Forwarded-For', '')
        ip = forwarded.split(',')[0].strip() if forwarded else self.client_address[0]
        now = datetime.datetime.now().isoformat(timespec='seconds')

        body = (
            "<!DOCTYPE html>\n"
            "<html><head><title>Hello</title></head><body>"
            "<h1>Hello, world</h1>"
            f"<p>Your IP: <code>{ip}</code></p>"
            f"<p>Commit ID: <code>{COMMIT_ID}</code></p>"
            f"<p>Server time: <code>{now}</code></p>"
            "</body></html>"
        )
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode('utf-8'))

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8080'))
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f'helloworld listening on :{port}', flush=True)
    server.serve_forever()
