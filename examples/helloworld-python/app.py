#!/usr/bin/env python3
"""Tiny hello-world server: shows visitor IP, commit ID, current time."""
import datetime
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

COMMIT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commit.txt')
try:
    with open(COMMIT_FILE) as f:
        COMMIT_ID = f.read().strip()
except FileNotFoundError:
    COMMIT_ID = 'unknown'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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
