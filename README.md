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
- A phone on the same tailnet or LAN.

## Run

```bash
export OPENCODE_USERNAME=opencode          # optional, this is the default
export OPENCODE_PASSWORD='<your-password>' # required; the proxy exits without it

python3 serve.py
```

Then open `http://<mac-tailscale-or-lan-ip>:8787` and enter the same username and
password in the Connect dialog.

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENCODE_PASSWORD` | none, required | password sent to the upstream server |
| `OPENCODE_SERVER_PASSWORD` | none | alternative name for the above |
| `OPENCODE_USERNAME` | `opencode` | basic-auth username |
| `OPENCODE_UPSTREAM_HOST` | `127.0.0.1` | where `opencode serve` listens |
| `OPENCODE_UPSTREAM_PORT` | `4096` | upstream port |
| `OPENCODE_SYNC_HOST` | `0.0.0.0` | listen address |
| `OPENCODE_SYNC_PORT` | `8787` | listen port |

Use the system interpreter on macOS (`/usr/bin/python3`) if a per-app firewall
such as LuLu blocks a uv- or Homebrew-managed Python on the Tailscale interface.

## Security

Read this before exposing the port.

- The proxy speaks **plain HTTP**. Over Tailscale the traffic is encrypted by
  WireGuard, but it is not TLS: no certificate, and browsers will mark the page
  "Not secure". Put it behind `tailscale serve`, Caddy, nginx, or an SSH tunnel if
  you want TLS.
- Every `/api/*` and `/global/*` request must carry the Basic `Authorization`
  header matching `OPENCODE_USERNAME` / `OPENCODE_PASSWORD`. Anything else gets
  `401` with a `WWW-Authenticate` challenge, compared in constant time. The static
  `index.html` itself is served without auth, so the login form can load.
- No CORS headers are sent. The UI is same-origin, and other origins cannot read
  proxied responses.
- The API it proxies can run shell commands through the agent. Treat the port as
  equivalent to a shell on the host, and do not expose it to the public internet.

Put it behind something that terminates TLS and checks credentials: `tailscale
serve`, Caddy, nginx, or an SSH tunnel. Do not expose it to the public internet.

## Layout

```
index.html   UI: sessions, transcript, folds, forms, attachments
serve.py     static host for index.html + reverse proxy to opencode serve
```
