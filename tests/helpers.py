"""Shared test helpers: tiny local HTTP/TLS servers and a throwaway certificate."""
from __future__ import annotations

import shutil
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server naming
        self.server.seen.append({"path": self.path, "host": self.headers.get("Host"), "ua": self.headers.get("User-Agent")})
        route = self.server.routes.get(self.path.split("?")[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, body = route
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


class LocalServer:
    """Serve ``routes`` ({path: (status, headers, body_bytes)}) on 127.0.0.1, optionally over TLS."""

    def __init__(self, routes, certfile: str | None = None, keyfile: str | None = None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.routes = routes
        self.httpd.seen = []
        if certfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile, keyfile)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.seen = self.httpd.seen
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_self_signed_cert(directory: str) -> tuple[str, str] | None:
    """Create cert.pem/key.pem for CN=localhost using the openssl CLI (None if unavailable)."""
    if not shutil.which("openssl"):
        return None
    cert, key = str(Path(directory) / "cert.pem"), str(Path(directory) / "key.pem")
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
         "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        capture_output=True,
    )
    return (cert, key) if result.returncode == 0 else None


def temp_dir():
    return tempfile.TemporaryDirectory()
