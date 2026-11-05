"""Web fingerprinting against a local HTTP server (server header, title, favicon hash)."""

from __future__ import annotations

import http.server
import threading

from rased.discovery.fphash import favicon_hash
from rased.webfp import fetch, fingerprint_asset

ICON = b"RASED-TEST-ICON-BYTES"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.end_headers()
            self.wfile.write(ICON)
        else:
            body = b'<html><head><title>  Router  Admin </title><link rel="icon" href="/favicon.ico"></head></html>'
            self.send_response(200)
            self.send_header("Server", "TestServer/1.0")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


def _server():  # type: ignore[no-untyped-def]
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_fetch_captures_server_title_favicon():
    srv, port = _server()
    try:
        r = fetch("127.0.0.1", port, use_https=False, timeout=5.0)
    finally:
        srv.shutdown()
    assert r["status"] == 200
    assert str(r["server"]).startswith("TestServer")
    assert r["title"] == "Router Admin"               # whitespace collapsed
    assert r["favicon_hash"] == favicon_hash(ICON)     # matches the primitive


def test_fingerprint_asset_filters_to_web_ports():
    # Non-web ports are never probed → empty result, no connection attempts.
    assert fingerprint_asset("127.0.0.1", [22, 3389, 445]) == []
