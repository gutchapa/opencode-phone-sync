#!/usr/bin/env python3
"""Tiny same-origin UI + reverse proxy to local OpenCode V2 serve.

Usage on the Mac (with opencode serve already on :4096):

  export OPENCODE_PASSWORD='<your-password>'   # or OPENCODE_SERVER_PASSWORD
  export OPENCODE_USERNAME='<your-username>'   # optional, default: opencode
  python3 serve.py                             # listens 0.0.0.0:8787

Phone / browser: https://<machine>.<tailnet>.ts.net
"""
from __future__ import annotations

import base64
import hmac
import http.client
import http.server
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import uuid

UPSTREAM_HOST = os.environ.get("OPENCODE_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("OPENCODE_UPSTREAM_PORT", "4096"))
LISTEN_HOST = os.environ.get("OPENCODE_SYNC_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("OPENCODE_SYNC_PORT", "8787"))
PASSWORD = (
    os.environ.get("OPENCODE_PASSWORD")
    or os.environ.get("OPENCODE_SERVER_PASSWORD")
    or ""
)
USERNAME = os.environ.get("OPENCODE_USERNAME", "opencode")
ROOT = os.path.dirname(os.path.abspath(__file__))
# Phone attachments are written here so the agent can open them by path
UPLOAD_DIR = os.environ.get("OPENCODE_UPLOAD_DIR") or os.path.join(ROOT, "uploads")
MAX_BODY = 32 * 1024 * 1024


def basic_auth_header() -> str:
    token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    return f"Basic {token}"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "opencode-phone-sync"
    sys_version = ""
    timeout = 30  # drop stalled clients instead of pinning a thread
    # Phone photos as base64 JSON can be several MB
    def __init__(self, *args, **kwargs):
        self.max_body = 32 * 1024 * 1024
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            return self._serve_index()
        if parsed.path.startswith("/api/") or parsed.path.startswith("/global/"):
            return self._proxy()
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/upload":
            return self._upload(parsed)
        if parsed.path.startswith("/api/"):
            return self._proxy()
        self.send_error(404, "Not found")

    def do_PATCH(self) -> None:
        return self.do_POST()

    def do_DELETE(self) -> None:
        return self.do_POST()

    def do_PUT(self) -> None:
        return self.do_POST()

    def _authorized(self) -> bool:
        got = (self.headers.get("Authorization") or "").encode()
        return hmac.compare_digest(got, basic_auth_header().encode())

    def _unauthorized(self) -> None:
        body = b'{"error":{"message":"unauthorized"}}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("WWW-Authenticate", 'Basic realm="opencode"')
        self.end_headers()
        self.wfile.write(body)

    def _serve_index(self) -> None:
        path = os.path.join(ROOT, "index.html")
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "img-src data: blob:; connect-src 'self'; base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        """Read the request body, or send an error and return None."""
        raw_len = (self.headers.get("Content-Length") or "0").strip()
        try:
            length = int(raw_len)
        except ValueError:
            self.send_error(400, "Bad Content-Length")
            return None
        if length < 0:
            self.send_error(400, "Bad Content-Length")
            return None
        if length > MAX_BODY:
            self.send_error(413, "Payload too large")
            return None
        return self.rfile.read(length) if length else b""

    def _upload(self, parsed: urllib.parse.ParseResult) -> None:
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            self.close_connection = True
            self.send_error(403, "Cross-site request rejected")
            return
        if not self._authorized():
            self.close_connection = True
            return self._unauthorized()
        body = self._read_body()
        if body is None:
            return
        name = urllib.parse.parse_qs(parsed.query).get("name", ["file"])[0]
        base = os.path.basename(name.replace("\\", "/"))
        base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:120] or "file"
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(UPLOAD_DIR, f"{stamp}-{uuid.uuid4().hex[:4]}-{base}")
        try:
            os.makedirs(UPLOAD_DIR, mode=0o700, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(body)
            os.chmod(dest, 0o600)
        except OSError as e:
            msg = f"upload failed: {e}".encode()
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        payload = json.dumps({"path": dest, "name": base, "bytes": len(body)}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _proxy(self) -> None:
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            self.close_connection = True
            self.send_error(403, "Cross-site request rejected")
            return
        if not self._authorized():
            self.close_connection = True
            return self._unauthorized()
        body = self._read_body()
        if body is None:
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"

        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=300)
        headers = {
            "Accept": self.headers.get("Accept", "application/json"),
            "Authorization": basic_auth_header(),
            "Connection": "close",
        }
        if body is not None:
            headers["Content-Type"] = self.headers.get("Content-Type", "application/json")
            headers["Content-Length"] = str(len(body))
        try:
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            msg = f"upstream error: {e}".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return
        finally:
            conn.close()

        self.send_response(resp.status)
        skip = {"transfer-encoding", "connection", "content-encoding"}
        for k, v in resp.getheaders():
            if k.lower() in skip:
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ReusableServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


def main() -> None:
    server = ReusableServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(
        f"OpenCode Sync UI on http://{LISTEN_HOST}:{LISTEN_PORT}\n"
        f"Proxying API → http://{UPSTREAM_HOST}:{UPSTREAM_PORT}\n"
        f"Auth user={USERNAME} (password from OPENCODE_PASSWORD)\n"
        f"Open on phone: http://<mac-tailscale-or-lan>:{LISTEN_PORT}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


if __name__ == "__main__":
    if not PASSWORD:
        print(
            "Set OPENCODE_PASSWORD (or OPENCODE_SERVER_PASSWORD) before starting.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        socket.getaddrinfo(LISTEN_HOST, LISTEN_PORT)
    except socket.gaierror as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    main()
