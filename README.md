# bupt-netaccount-transfer-service

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](#prerequisites)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#prerequisites)
[![Target: BUPT aTrust](https://img.shields.io/badge/target-BUPT%20aTrust%20VPN-c8102e.svg)](#)

**English** | [中文](README.zh-CN.md)

A headless keep-alive companion for **BUPT's Sangfor aTrust SSL-VPN**
(`vpn.bupt.edu.cn`). Automates the `netaccount.bupt.edu.cn` TOTP login
via a one-click cookie capture from WeChat, polls `/otp` at the
portal's own JS cadence, drives the aTrust GUI on a dedicated server
box — and ships a tiny HTTPS / TCP gateway so workstations that can't
install the VPN client themselves can still reach BUPT intranet HTTP(S)
sites and SSH hosts through that server.

> **Scope.** Designed for and tested against BUPT (Beijing University
> of Posts and Telecommunications). The same `/otp + aTrust` pattern
> may exist at other institutions; all institution-specific values are
> CLI-overridable (`--target-host`, `--vpn-url`, `--keepalive-url`),
> but defaults and UI text expectations are BUPT-specific.

---

## What it does

A small toolkit that splits cleanly into two independent halves:

| Half | Solves | Lives in |
|---|---|---|
| **OTP automation** | Keep the BUPT aTrust VPN tunnel logged in 24/7 on a dedicated server. A WeChat one-click on the workstation captures the `netaccount.bupt.edu.cn` session cookie; the server then polls `/otp` on that cookie and drives the aTrust GUI with each fresh 6-digit code. | `local/`, `server/`, `shared/`, `run_a.sh`, `run_b.sh` |
| **Access gateway** | From the workstation, reach BUPT intranet HTTP / HTTPS sites and SSH hosts that are only routable through the VPN tunnel on the server. | `gateway/` |

The two halves don't depend on each other. You can run the gateway
even if you log in to aTrust manually, and vice versa.

### Why this project exists

BUPT's aTrust VPN authentication is a stateful chain of (a) WeChat-side
WeCom binding → (b) browser session cookie on `netaccount.bupt.edu.cn`
→ (c) 30-second TOTP from `/otp` → (d) typed into the desktop aTrust
client. Steps (a)+(b) cannot be scripted (the binding is bound to a
WeChat-controlled SSO step); steps (c)+(d) can. This project closes
that gap so the desktop aTrust client can be parked on a server and
re-authenticated automatically every time the VPN session expires,
without manual TOTP entry.

---

## Architecture

```
  WORKSTATION (A)                              SERVER (B)
  ═══════════════                              ═══════════════
                                               ┌──────────────────────────┐
  bash run_a.sh ◀────── A↔B TLS link ────────▶ │  run_b.sh + atrust_setup │
   ├─ mitm_capture.py    cookie + refresh      │   - drives aTrust UI     │
   └─ mitmproxy addon    via _link.py (mTLS)   │   - keepalive probe      │
       (one-shot capture                       │   - re-runs on disconnect│
        of WeChat-side                         │  otp_poller.py           │
        /otp cookie)                           │   - polls /otp every     │
                                               │     ~30s with the cookie │
                                               │   - serves OTP locally   │
                                               │     to atrust_setup      │
                                               └──────────────────────────┘
                                                              ▲
                                                              │ aTrust VPN tunnel
                                                              ▼
                                               ╔══════════════════════════╗
                                               ║       INTRANET           ║
                                               ║  (your institution)      ║
  browser ─────── HTTP/HTTPS ──────────┐                                  ║
                                       │       ┌──────────────────────────╣
                       gateway/        ▼       │  gateway/server.py       ║
                       server.py    :80/:443──▶│   - HTTPS forward proxy  ║
                       (no client                  - /?url=<target>       ║
                        install)                   - mints leaf certs     ║
                                                   under its own CA       ║
                                                                          ║
  VSCode / ssh ─── TCP ─── :<port> ─────────────▶  gateway/tcp_forward.py ║
                                                   - raw TCP splice       ║
                                                   - --target host:port   ║
                                               ╚══════════════════════════╝
```

Each green box is an independent Python process you spawn separately,
so failure of one doesn't bring down the others.

---

## Prerequisites

**On the workstation (A)** (Windows):

- Python 3.10+ with `pip install requests mitmproxy cryptography paramiko`
- Git Bash (for the `bash run_*.sh` launchers)
- WeChat — only for the OTP-automation half; A captures the captive-portal
  cookie when you click its link inside WeChat

**On the server (B)** (Windows, network-routable from A):

- Python 3.10+ with `pip install requests cryptography pywinauto psutil mitmproxy`
- Sangfor aTrust desktop client at
  `C:\Program Files (x86)\Sangfor\aTrust\aTrustTray\aTrustTray.exe`
- A real account on your aTrust VPN
- Inbound TCP ports you choose (defaults: 6000/6001 for A↔B, 80/443 for
  the gateway, and whatever ports you assign to `tcp_forward.py`).
  Open them in Windows Firewall **and** your cloud security group.

---

## Half 1 — OTP automation

### What happens

1. **A's `mitm_capture.py`** starts in capture mode. It briefly enables
   itself as the HKCU HTTP proxy and runs `mitmdump` with an addon.
2. The operator opens the captive-portal link inside WeChat on A.
   WeChat's embedded browser sends the request through the proxy.
3. The addon lifts the session `Cookie` header off the first `/otp`
   request and sends it to A's parent process, which forwards it over a
   mTLS connection to B's `otp_poller.py`.
4. `otp_poller.py` on B now owns a long-running `requests.Session` and
   polls `/otp` every ~30s — the same cadence the portal's own
   JavaScript uses. Each response yields a 6-digit TOTP plus a remaining
   lifetime.
5. **`atrust_setup.py`** on B drives the aTrust GUI via `pywinauto`: it
   walks the URL-config dialog, ticks the terms checkbox, types the
   username, types the OTP (re-verifying freshness against B
   immediately before clicking 登录), and detects success/failure.
6. After login, `atrust_setup.py` enters a keepalive loop probing
   intranet URLs you supply. If all probes fail it kills aTrust and
   re-runs the whole flow.

### Run it

```bash
# On B (the VPN server):
bash run_b.sh \
    --port <B_LISTEN_PORT> \
    --peer-port <A_LISTEN_PORT> --peer-host <A_REACHABLE> \
    --target-host <YOUR_CAPTIVE_PORTAL_HOST> \
    --vpn-url     <YOUR_ATRUST_PORTAL_URL>
```

```bash
# On A (your workstation):
bash run_a.sh \
    --port <A_LISTEN_PORT> \
    --peer-port <B_LISTEN_PORT> --peer-host <B_REACHABLE> \
    --target-host <YOUR_CAPTIVE_PORTAL_HOST>
```

Flag glossary:

| Flag | Meaning | BUPT default |
|---|---|---|
| `--port N` | Local listener (this side's TLS link endpoint) | — |
| `--peer-port N` | The other side's listener port (where we dial) | — |
| `--peer-host H` | The other side's reachable host / IP | — |
| `--target-host H` | Captive-portal whose `/otp` we poll. Must match between A and B. | `netaccount.bupt.edu.cn` |
| `--vpn-url U` | aTrust portal URL (typed into the access-address dialog). B-side only. | `https://vpn.bupt.edu.cn` |

`run_b.sh` also accepts `takeover` / `stop` / `status` subcommands.
`Ctrl+B` while attached detaches the workers; `Ctrl+C` tears down.

### Other launchers

- `run_test_local.sh` — A + B + setup on one machine for end-to-end UI
  testing without touching production. Skips the final 登录 click.
- `run_test_seperate.sh` — B-only test variant. Pair with `run_a.sh`
  for a real client.

### Keepalive probes

`atrust_setup.py` ships with BUPT campus URLs as defaults
(`cwxt.bupt.edu.cn`, `tv.byr.cn`, `my.bupt.edu.cn`, `software.bupt.edu.cn`,
`zzgz.bupt.edu.cn`) — picked for diversity so a single-system outage
doesn't false-positive as "VPN down". Override via `--keepalive-url URL`
(repeatable), or edit the `KEEPALIVE_URLS` constant at the top of
`server/atrust_setup.py` if you're adapting to a different institution:

```bash
python C:/work/server/atrust_setup.py \
    --url <YOUR_ATRUST_PORTAL_URL> \
    --keepalive-url http://intranet1.example.org/ \
    --keepalive-url http://intranet2.example.org/login
```

`run_b.sh` does **not** forward `--keepalive-url` for you; edit the
constant or invoke `atrust_setup.py` directly.

---

## Half 2 — Access gateway

### `gateway/server.py` — HTTPS URL-forwarding API

Listens on port 80 (HTTP) and 443 (HTTPS) on the server. Each request
URL carries a `?url=<target>` query parameter; the gateway fetches that
target server-side (through the aTrust tunnel) and streams the response
back verbatim.

Browser usage:

    https://<SERVER>/?url=https://intranet.example.org/some/path

URL-encode the target if it contains its own `?`, `&`, or `#`.

Sub-resource resolution is three-tier so relative URLs inside a proxied
HTML page (CSS, fonts, AJAX, ...) still flow through the gateway:

1. Explicit `?url=...`
2. `Referer` carrying a `?url=...` (HTML's relative links)
3. `__gw_origin` cookie set by the gateway on a previous response
   (CSS-referenced fonts and images, whose Referer is the CSS file URL)

Absolute `Location:` headers in 3xx responses are rewritten so the
browser stays inside the gateway.

#### Run it

```bash
python C:/work/gateway/server.py \
    [--http-port 80] [--https-port 443] \
    [--public-host <CERT_SAN_HOSTNAME>]
```

`--public-host` controls only the SAN of the self-signed cert minted on
first start (stored in `%APPDATA%\atrust-vpn\certs\gateway.{crt,key}`).
The cert is self-signed; browsers will warn — click through. The
gateway re-fetches the target over its own real TLS handshake
internally, so the warning is purely about the trust path between your
browser and the gateway, not about the target.

#### Limitations

- The gateway has **no authentication**. Anyone who can reach
  ports 80/443 on the server can use it. Lock down at firewall /
  cloud security group level.
- Absolute links to upstream domains that appear inside HTML bodies
  are not rewritten. Clicking such a link in a returned page makes the
  browser go to the real upstream directly, which will fail from the
  workstation. Pages with mostly relative URLs (most modern web apps)
  work fine.
- WebSocket / Server-Sent Events / chunked streaming are buffered
  (whole-body before relay).

### `gateway/tcp_forward.py` — raw TCP port forwarder

A plain bidirectional TCP splice. Useful for non-TLS protocols (SSH,
FTP control, MySQL, ...) where the application layer doesn't care
about TLS interception.

```bash
python C:/work/gateway/tcp_forward.py \
    --listen-port <N> --target <INTRANET_HOST>:22
```

Then on your workstation:

```bash
ssh -p <N> user@<SERVER>          # equivalent to ssh user@<INTRANET_HOST>
```

For VSCode Remote-SSH, the simplest setup is to make the **alias** in
`~/.ssh/config` match what VSCode already knows as a Linux host:

```
Host <INTRANET_HOST_ALIAS>
    HostName <SERVER>
    Port <N>
    User <user>
```

Connect from VSCode to `<INTRANET_HOST_ALIAS>`. Don't connect by IP
literal of the server, or VSCode will use the server's `remotePlatform`
mapping (probably Windows) and try to spawn `powershell` on a Linux
target.

---

## Data layout

Persistent runtime state lives under `%APPDATA%\atrust-vpn\` on Windows
(or `~/.atrust-vpn/` on POSIX), kept out of the source tree:

```
%APPDATA%\atrust-vpn\
├── certs\
│   ├── link.crt + link.key       — A↔B mTLS material (same pair on both)
│   ├── local.crt + local.key     — B↔setup loopback channel (B-only)
│   └── gateway.crt + gateway.key — gateway HTTPS self-signed (B-only)
├── logs\
│   ├── a.log b.log setup.log mitm.log gateway.log tcp_forward.log
└── state\
    ├── *.pid                     — PID files for the runner
    ├── capture.flag              — mitm-capture-mode marker
    └── proxy_backup.json         — restored on exit
```

Override the base path with the `ATRUST_VPN_DATA` env var if you need
to relocate it.

---

## Operational notes

- **First-time deploy on B**: `run_b.sh` mints `link.crt + link.key`
  on first launch. Copy this pair to A under the same path
  (`%APPDATA%\atrust-vpn\certs\`). A side will fail loudly if missing.
- **mitmproxy CA on A**: `run_a.sh` installs `mitmproxy-ca.cer` into the
  current-user Trusted Root automatically (silent if already trusted).
  Required for the cookie-capture mitmdump step.
- **Detach / re-attach** workers via `Ctrl+B` then
  `bash run_b.sh takeover`.
- **Stop everything**: `bash run_b.sh stop` (or `run_a.sh stop`).
  `_runner.sh` also kills orphan `tail` / `awk` pipes from prior
  abnormal exits.

---

## File map

```
bupt-netaccount-transfer-service/
├── LICENSE                         MIT
├── README.md                       this file
├── README.zh-CN.md                 Chinese translation
├── _paths.sh                       shell mirror of shared/_paths.py
├── run_a.sh                        A-side launcher
├── run_b.sh                        B-side launcher (otp_poller + atrust_setup)
├── run_test_local.sh               local A + B + setup integration test
├── run_test_seperate.sh            B-only test
├── local/
│   ├── mitm_capture.py             A: cookie capture orchestrator
│   └── _otp_addon.py               A: mitmdump addon — sniffs /otp + parses ID
├── server/
│   ├── otp_poller.py               B: /otp polling daemon
│   ├── atrust_setup.py             B: aTrust UI driver + keepalive
│   └── record_popup.py             B: passive UIA event recorder (debug)
├── shared/
│   ├── _paths.py / _paths.sh       runtime path resolver
│   ├── _link.py                    mTLS helpers (cert gen + send/serve)
│   ├── _spawn.py                   Windows-detached process spawner
│   ├── _runner.sh                  worker registry / attach / kill_all helpers
│   └── _env.ps1                    HKCU proxy backup/restore + kill_all
└── gateway/
    ├── server.py                   HTTPS URL-forwarding API
    └── tcp_forward.py              raw TCP port forwarder
```

---

## Contributing & community

Pull requests, issues, and questions are **all welcome** — this is a
small focused project, exactly the kind that benefits most from outside
eyes and real deployment reports.

- **Found a bug?** Open an issue with reproduction steps + the relevant
  log file (`a.log` / `b.log` / `setup.log` / `gateway.log`).
- **Have a question?** GitHub Issues / Discussions are both fine; no
  question is too small.
- **Want a feature?** Open an issue first to talk through design, then
  send a PR.
- **Adapting it for a non-BUPT institution?** Please share what
  `--target-host` / `--vpn-url` / `--keepalive-url` set you ended up
  using — it makes the project useful to others in similar situations.
- **Forking for your own variant?** Go for it. The codebase is small
  and deliberately avoids heavy frameworks; it should be easy to read,
  easy to modify, and easy to make your own.

A few style notes if you're sending a PR:

- One focused change per commit, please.
- Keep the existing module boundaries: `local/` (A-side),
  `server/` (B-side), `shared/`, and `gateway/` should not start
  importing each other beyond what's already in `shared/`.
- **Never commit personal credentials, server IPs, account IDs, or
  any operational secret** — even in comments or example outputs.
  Use the existing CLI knobs.
- Tests live in `run_test_local.sh` / `run_test_seperate.sh`; please
  keep them passing.

The project's long-term health depends on people running it in
production, hitting edge cases, and reporting back. If you've got a
working deployment, drop a note on the issue tracker — it helps more
than you'd think.

## License

MIT — see [LICENSE](LICENSE).
