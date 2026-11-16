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
import struct
import sys
import threading
import time
import urllib.parse
import uuid

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAVE_PUSH = True
except Exception:  # no cryptography: the notification endpoint reports unavailable
    HAVE_PUSH = False

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
STATIC_ASSETS = {
    "/sw.js": "text/javascript; charset=utf-8",
    "/manifest.webmanifest": "application/manifest+json",
    "/icon-192.png": "image/png",
    "/icon-512.png": "image/png",
    "/apple-touch-icon.png": "image/png",
}
# Notification state: VAPID key + browser subscriptions
PUSH_STATE = os.environ.get("OPENCODE_PUSH_STATE") or os.path.join(ROOT, "push-state.json")
PENDING = {}  # session id -> start time (ms) of a turn we should announce
PENDING_LOCK = threading.Lock()


def basic_auth_header() -> str:
    token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    return f"Basic {token}"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def load_push_state() -> dict:
    try:
        with open(PUSH_STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_push_state(state: dict) -> None:
    tmp = PUSH_STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PUSH_STATE)


def vapid_private() -> "ec.EllipticCurvePrivateKey":
    state = load_push_state()
    if not state.get("private_key"):
        key = ec.generate_private_key(ec.SECP256R1())
        state["private_key"] = b64u(key.private_numbers().private_value.to_bytes(32, "big"))
        save_push_state(state)
    return ec.derive_private_key(
        int.from_bytes(b64u_decode(state["private_key"]), "big"), ec.SECP256R1()
    )


def vapid_public_bytes(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def vapid_authorization(endpoint: str, key) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    header = {"typ": "JWT", "alg": "ES256"}
    claims = {
        "aud": f"{parsed.scheme}://{parsed.netloc}",
        "exp": int(time.time()) + 12 * 3600,
        "sub": "mailto:opencode@localhost",
    }
    signing = (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(claims, separators=(",", ":")).encode())
    )
    der = key.sign(signing.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    jwt = signing + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"vapid t={jwt}, k={b64u(vapid_public_bytes(key))}"


def encrypt_push(subscription: dict, payload: bytes) -> bytes:
    """RFC 8291 aes128gcm body for one browser subscription."""
    ua_public = b64u_decode(subscription["keys"]["p256dh"])
    auth = b64u_decode(subscription["keys"]["auth"])
    eph = ec.generate_private_key(ec.SECP256R1())
    eph_public = vapid_public_bytes(eph)
    shared = eph.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    )
    ikm = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=auth,
        info=b"WebPush: info\x00" + ua_public + eph_public,
    ).derive(shared)
    salt = os.urandom(16)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
               info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt,
                 info=b"Content-Encoding: nonce\x00").derive(ikm)
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + struct.pack(">I", 4096) + bytes([len(eph_public)]) + eph_public + ciphertext


def send_push(title: str, body: str, url: str = "/") -> int:
    """Deliver to every stored subscription; drop ones the service revoked."""
    if not HAVE_PUSH:
        return 0
    state = load_push_state()
    subs = state.get("subscriptions") or []
    if not subs:
        return 0
    key = vapid_private()
    payload = json.dumps({"title": title, "body": body, "url": url}).encode()
    dead, sent = [], 0
    for sub in subs:
        try:
            endpoint = sub["endpoint"]
            parsed = urllib.parse.urlparse(endpoint)
            path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            conn = http.client.HTTPSConnection(parsed.netloc, timeout=15)
            try:
                conn.request(
                    "POST",
                    path,
                    body=encrypt_push(sub, payload),
                    headers={
                        "Authorization": vapid_authorization(endpoint, key),
                        "Content-Encoding": "aes128gcm",
                        "Content-Type": "application/octet-stream",
                        "TTL": "86400",
                        "Urgency": "normal",
                    },
                )
                resp = conn.getresponse()
                resp.read()
                if resp.status in (404, 410):
                    dead.append(sub)
                elif 200 <= resp.status < 300:
                    sent += 1
            finally:
                conn.close()
        except Exception as e:
            sys.stderr.write(f"push: delivery failed: {e}\n")
    if dead:
        state["subscriptions"] = [s for s in subs if s not in dead]
        save_push_state(state)
    return sent


def upstream_get(path: str) -> dict:
    conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=15)
    try:
        conn.request("GET", path, headers={"Authorization": basic_auth_header(), "Accept": "application/json"})
        resp = conn.getresponse()
        return json.loads(resp.read() or b"{}")
    finally:
        conn.close()


def check_pending() -> None:
    with PENDING_LOCK:
        watched = list(PENDING.items())
    for sid, started in watched:
        try:
            info = upstream_get(f"/api/session/{urllib.parse.quote(sid)}")
        except Exception:
            continue
        data = info.get("data") or info
        timing = data.get("time") or {}
        idle = timing.get("idle") or 0
        if not idle or idle < started:
            continue
        with PENDING_LOCK:
            PENDING.pop(sid, None)
        title = data.get("title") or "session"
        sys.stderr.write(f"push: session finished: {title}\n")
        send_push("OpenCode finished", title, f"/?session={urllib.parse.quote(sid)}")


def watch_loop() -> None:
    """Announce a session when the turn that was just started finishes."""
    while True:
        time.sleep(3)
        check_pending()


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
        if parsed.path == "/push/key":
            return self._push_key()
        if parsed.path in STATIC_ASSETS:
            return self._serve_static(parsed.path, STATIC_ASSETS[parsed.path])
        if parsed.path.startswith("/api/") or parsed.path.startswith("/global/"):
            return self._proxy()
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/upload":
            return self._upload(parsed)
        if parsed.path == "/push/subscribe":
            return self._push_subscribe(parsed)
        if parsed.path == "/push/unsubscribe":
            return self._push_unsubscribe(parsed)
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

    def _serve_static(self, path: str, content_type: str) -> None:
        file_path = os.path.join(ROOT, path.lstrip("/"))
        try:
            with open(file_path, "rb") as f:
                body = f.read()
        except OSError:
            self.send_error(404, "Not found")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if path == "/sw.js":
            self.send_header("Service-Worker-Allowed", "/")
        self.end_headers()
        self.wfile.write(body)

    def _push_key(self) -> None:
        payload = json.dumps({
            "enabled": HAVE_PUSH,
            "key": b64u(vapid_public_bytes(vapid_private())) if HAVE_PUSH else "",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _push_subscribe(self, parsed) -> None:
        if not self._authorized():
            self.close_connection = True
            return self._unauthorized()
        body = self._read_body()
        if body is None:
            return
        try:
            sub = json.loads(body or b"{}")
            endpoint = sub["endpoint"]
            sub["keys"]["p256dh"]
            sub["keys"]["auth"]
        except Exception:
            self.send_error(400, "Bad subscription")
            return
        state = load_push_state()
        subs = [s for s in state.get("subscriptions") or [] if s.get("endpoint") != endpoint]
        subs.append({"endpoint": endpoint, "keys": sub["keys"]})
        state["subscriptions"] = subs[-20:]
        save_push_state(state)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _push_unsubscribe(self, parsed) -> None:
        if not self._authorized():
            self.close_connection = True
            return self._unauthorized()
        body = self._read_body()
        if body is None:
            return
        try:
            endpoint = json.loads(body or b"{}")["endpoint"]
        except Exception:
            self.send_error(400, "Bad subscription")
            return
        state = load_push_state()
        state["subscriptions"] = [s for s in state.get("subscriptions") or []
                                  if s.get("endpoint") != endpoint]
        save_push_state(state)
        self.send_response(204)
        self.end_headers()

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
            "img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; "
            "manifest-src 'self'; base-uri 'none'; "
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

        if self.command == "POST" and 200 <= resp.status < 300:
            started = re.fullmatch(r"/api/session/([^/]+)/(?:prompt|command)", parsed.path)
            if started:
                with PENDING_LOCK:
                    PENDING[urllib.parse.unquote(started.group(1))] = int(time.time() * 1000)

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
        f"Notifications: {'enabled' if HAVE_PUSH else 'unavailable (no cryptography)'}\n"
        f"Open on phone: http://<mac-tailscale-or-lan>:{LISTEN_PORT}",
        flush=True,
    )
    if HAVE_PUSH:
        threading.Thread(target=watch_loop, daemon=True).start()
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
