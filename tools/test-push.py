#!/usr/bin/env python3
"""Offline checks for the Web Push code in serve.py (no network, no browser)."""
import base64
import json
import os
import struct
import sys
import tempfile

os.environ.setdefault("OPENCODE_PASSWORD", "test")
tmp = tempfile.mkdtemp()
os.environ["OPENCODE_PUSH_STATE"] = os.path.join(tmp, "push-state.json")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import serve  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

assert serve.HAVE_PUSH, "cryptography missing"

browser = ec.generate_private_key(ec.SECP256R1())
ua_public = browser.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
)
auth = os.urandom(16)
sub = {
    "endpoint": "https://push.example.invalid/sub",
    "keys": {"p256dh": serve.b64u(ua_public), "auth": serve.b64u(auth)},
}

payload = json.dumps({"title": "OpenCode finished", "body": "demo"}).encode()
body = serve.encrypt_push(sub, payload)

# Decrypt exactly as a user agent would (RFC 8291)
salt, rs, idlen = body[:16], struct.unpack(">I", body[16:20])[0], body[20]
eph_public = body[21:21 + idlen]
ciphertext = body[21 + idlen:]
assert rs == 4096 and idlen == 65, (rs, idlen)
eph = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_public)
shared = browser.exchange(ec.ECDH(), eph)
ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth,
           info=b"WebPush: info\x00" + ua_public + eph_public).derive(shared)
cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt,
           info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt,
             info=b"Content-Encoding: nonce\x00").derive(ikm)
plain = AESGCM(cek).decrypt(nonce, ciphertext, None)
assert plain.endswith(b"\x02") and json.loads(plain[:-1]) == json.loads(payload)
print("encrypt/decrypt round trip ok")

# VAPID JWT verifies against the advertised public key
key = serve.vapid_private()
header = serve.vapid_authorization("https://push.example.invalid/sub", key)
jwt = header.split("t=")[1].split(",")[0].strip()
signing, sig = jwt.rsplit(".", 1)
r = int.from_bytes(serve.b64u_decode(sig)[:32], "big")
s = int.from_bytes(serve.b64u_decode(sig)[32:], "big")
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
key.public_key().verify(encode_dss_signature(r, s), signing.encode(), ec.ECDSA(hashes.SHA256()))
claims = json.loads(serve.b64u_decode(signing.split(".")[1]))
assert claims["aud"] == "https://push.example.invalid" and claims["exp"] > 0
assert serve.b64u(serve.vapid_public_bytes(key)) in header
print("vapid jwt ok:", claims["aud"])

# Completion watcher fires once, only after idle passes the start time
sent = []
serve.send_push = lambda title, body, url="/": sent.append((title, body, url)) or 1
serve.PENDING["ses_test"] = 1000
serve.upstream_get = lambda path: {"data": {"title": "demo session", "time": {"idle": 999}}}
serve.check_pending()
assert not sent and "ses_test" in serve.PENDING, "fired before idle"
serve.upstream_get = lambda path: {"data": {"title": "demo session", "time": {"idle": 1000}}}
serve.check_pending()
assert sent and "ses_test" not in serve.PENDING, "did not fire"
serve.check_pending()
assert len(sent) == 1, "fired twice"
print("watcher ok:", sent[0])

# Subscription storage round trip
state = serve.load_push_state()
state["subscriptions"] = [sub]
serve.save_push_state(state)
assert os.stat(serve.PUSH_STATE).st_mode & 0o777 == 0o600
assert serve.load_push_state()["subscriptions"][0]["endpoint"] == sub["endpoint"]
print("push-state ok, mode 600")
print("ALL OK")
