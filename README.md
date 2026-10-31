# opencode-phone-sync

A phone-friendly web UI for a local [OpenCode](https://opencode.ai) server, plus a
tiny stdlib-only reverse proxy that supplies the upstream credentials.

Two files: `index.html` (single-file UI) and `serve.py` (proxy + static host).

## Why

The OpenCode UI is built for a terminal or desktop. This lets you read a running
session and send messages from a phone, over Tailscale or your LAN, without a
middleman app, without ads, and with attachments.

## Features

- Transcript of the recent messages of any session, newest at the bottom.
- Tool calls and their output in collapsible folds; `question` folds open by
  default so the question body is readable.
- Pending question forms render as cards: single select, multi-select, boolean,
  text, and free-text override, with `Send` and `Don't answer`.
- Stop button that interrupts the running turn.
- Photo and file attachments, inlined as base64 `file` parts (32 MB request cap,
  images downscaled to 1600 px).
- Per-message timestamps in the browser's local timezone.
- No external assets, no telemetry, no CDN, no framework.

## Requirements

- Python 3.9+ on the machine running the proxy. No third-party packages.
- A running `opencode serve` reachable on `127.0.0.1:4096` by default.
- A phone on the same Tailscale tailnet. The proxy binds to loopback and is
  reached through `tailscale serve`, which supplies TLS. Any equivalent private
  network plus a TLS terminator works too; do not expose the port publicly.

## Run

```bash
export OPENCODE_USERNAME=opencode          # optional, this is the default
export OPENCODE_PASSWORD='<your-password>' # required; the proxy exits without it
export OPENCODE_SYNC_HOST=127.0.0.1        # loopback only; reach it through tailscale serve

python3 serve.py
```

Then open `https://<machine>.<tailnet>.ts.net` and enter the same username and
password in the Connect dialog.

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENCODE_PASSWORD` | none, required | password required from clients and sent upstream |
| `OPENCODE_SERVER_PASSWORD` | none | alternative name for the above |
| `OPENCODE_USERNAME` | `opencode` | basic-auth username |
| `OPENCODE_UPSTREAM_HOST` | `127.0.0.1` | where `opencode serve` listens |
| `OPENCODE_UPSTREAM_PORT` | `4096` | upstream port |
| `OPENCODE_SYNC_HOST` | `0.0.0.0` | listen address; use `127.0.0.1` with tailscale serve |
| `OPENCODE_SYNC_PORT` | `8787` | listen port |

Use the system interpreter on macOS (`/usr/bin/python3`) if a per-app firewall
such as LuLu blocks a uv- or Homebrew-managed Python on the Tailscale interface.

## HTTPS with Tailscale (recommended)

Plain HTTP over Tailscale is encrypted by WireGuard but browsers still call it
insecure, and a direct LAN IP is plaintext. Terminate TLS with `tailscale serve`
and keep the proxy on loopback:

```bash
# once, in the Tailscale admin console: DNS -> HTTPS Certificates -> Enable HTTPS
tailscale serve --bg --https=443 http://127.0.0.1:8787
tailscale serve status
```

The UI is then at `https://<machine>.<tailnet>.ts.net`, certificate issued by
Let's Encrypt and renewed automatically, reachable from your tailnet only. The
proxy on `127.0.0.1:8787` is not reachable from the LAN or from other tailnet
nodes directly.

`tailscale serve` keeps its configuration across reboots. The proxy itself does
not, unless you run it as a login agent.

## Run at login (macOS, optional)

`run.sh` reads the password from the login Keychain, so no secret sits in a plist
or in shell history.

```bash
security add-generic-password -s opencode-phone-sync -a opencode -w  # prompts once

mkdir -p ~/opencode-phone-sync
cp serve.py index.html run.sh ~/opencode-phone-sync/
cp launchd/local.opencode-phone-sync.plist ~/Library/LaunchAgents/
# replace YOUR_USER in the plist with your short username, then:
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.opencode-phone-sync.plist
```

`KeepAlive` restarts the proxy if it exits. Check it with:

```bash
launchctl print gui/$(id -u)/local.opencode-phone-sync | grep -E "state|pid"
tail -n 20 ~/opencode-phone-sync/launchd.log
```

To stop it: `launchctl bootout gui/$(id -u)/local.opencode-phone-sync`.

## Security

Read this before exposing the port.

- Serve it over TLS. With `tailscale serve` that is automatic and tailnet-only;
  without TLS the Basic-auth header is protected only by the underlying VPN.
- Every `/api/*` and `/global/*` request must carry the Basic `Authorization`
  header matching `OPENCODE_USERNAME` / `OPENCODE_PASSWORD`. Anything else gets
  `401` with a `WWW-Authenticate` challenge, compared with
  `hmac.compare_digest`. The static `index.html` is served without auth so the
  login form can load.
- Requests arriving with `Sec-Fetch-Site: cross-site` are rejected with `403`,
  which blocks drive-by form posts from other sites. Command-line clients do not
  send that header and are unaffected.
- No CORS headers are sent. The UI is same-origin, and other origins cannot read
  proxied responses.
- The static page is served with `Content-Security-Policy`
  (`default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
  img-src data: blob:; connect-src 'self'`), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and no `Server`
  version banner.
- Message bodies are stripped of HTML through an inert `DOMParser` document, so
  markup in model output cannot run scripts or trigger image loads.
- Request bodies are capped at 32 MB, malformed `Content-Length` values get
  `400`, and idle sockets time out after 30 s.
- The API it proxies can run shell commands through the agent. Treat the port as
  equivalent to a shell on the host, and do not expose it to the public internet.

Known limitations, by design: there is no rate limiting on the auth check, the
browser keeps the password in `localStorage` so it is readable by any script that
manages to run in the page, and a single shared Basic credential is used rather
than per-user accounts.

Put it behind something that terminates TLS and checks credentials: `tailscale
serve`, Caddy, nginx, or an SSH tunnel. Do not expose it to the public internet.

## Layout

```
index.html   UI: sessions, transcript, folds, forms, attachments
serve.py     static host for index.html + reverse proxy to opencode serve
```
