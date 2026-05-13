# bupt-netaccount-transfer-service

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](#prerequisites)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#prerequisites)
[![Target: BUPT aTrust](https://img.shields.io/badge/target-BUPT%20aTrust%20VPN-c8102e.svg)](#)
[![Release](https://img.shields.io/github/v/release/AsmirZaric/bupt-netaccount-transfer-service)](https://github.com/AsmirZaric/bupt-netaccount-transfer-service/releases)

> Click a section header below to switch language · 点击下方任一标题切换语言

---

<details open>
<summary><h2 style="display:inline-block">🇺🇸 English</h2></summary>

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

### What it does

A small toolkit that splits cleanly into two independent halves:

| Half | Solves | Lives in |
|---|---|---|
| **OTP automation** | Keep the BUPT aTrust VPN tunnel logged in 24/7 on a dedicated server. A WeChat one-click on the workstation captures the `netaccount.bupt.edu.cn` session cookie; the server then polls `/otp` on that cookie and drives the aTrust GUI with each fresh 6-digit code. | `local/`, `server/`, `shared/`, `run_a.sh`, `run_b.sh` |
| **Access gateway** | From the workstation, reach BUPT intranet HTTP / HTTPS sites and SSH hosts that are only routable through the VPN tunnel on the server. | `gateway/` |

The two halves don't depend on each other. You can run the gateway
even if you log in to aTrust manually, and vice versa.

#### Why this project exists

BUPT's aTrust VPN authentication is a stateful chain of (a) WeChat-side
WeCom binding → (b) browser session cookie on `netaccount.bupt.edu.cn`
→ (c) 30-second TOTP from `/otp` → (d) typed into the desktop aTrust
client. Steps (a)+(b) cannot be scripted (the binding is bound to a
WeChat-controlled SSO step); steps (c)+(d) can. This project closes
that gap so the desktop aTrust client can be parked on a server and
re-authenticated automatically every time the VPN session expires,
without manual TOTP entry.

### Architecture

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

### Prerequisites

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

### Half 1 — OTP automation

#### What happens

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

#### Run it

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

#### Other launchers

- `run_test_local.sh` — A + B + setup on one machine for end-to-end UI
  testing without touching production. Skips the final 登录 click.
- `run_test_seperate.sh` — B-only test variant. Pair with `run_a.sh`
  for a real client.

#### Keepalive probes

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

### Half 2 — Access gateway

#### `gateway/server.py` — HTTPS URL-forwarding API

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

##### Run it

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

##### Limitations

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

#### `gateway/tcp_forward.py` — raw TCP port forwarder

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

### Data layout

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

### Operational notes

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

### File map

```
bupt-netaccount-transfer-service/
├── LICENSE                         MIT
├── README.md                       this file (bilingual via <details>)
├── CHANGELOG.md                    Keep-a-Changelog release notes
├── pyproject.toml                  PEP 621 project metadata + deps
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

### Contributing & community

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

### License

MIT — see [LICENSE](LICENSE).

</details>

<details>
<summary><h2 style="display:inline-block">🇨🇳 简体中文</h2></summary>

**专为北京邮电大学(BUPT)Sangfor aTrust SSL-VPN**(`vpn.bupt.edu.cn`)
开发的无人值守保活方案。自动化 `netaccount.bupt.edu.cn` 的 TOTP 登录(由
微信侧一次性 cookie 抓取触发),按门户自己 JS 的节奏轮询 `/otp`,在
专用服务器上驱动 aTrust GUI 完成登录;并附带一个轻量 HTTPS / TCP
gateway,让没装 VPN 客户端的工作站也能透过已在隧道内的服务器访问
BUPT 内网 HTTP(S) 站点和 SSH 主机。

> **适用范围**:为北京邮电大学(BUPT)设计并测试。其他机构如果用同样
> 的 `/otp + aTrust` 模式也许能复用,所有机构相关值都支持 CLI 覆盖
> (`--target-host` / `--vpn-url` / `--keepalive-url`),但默认值和
> UI 中文文本判断都基于 BUPT。

### 它解决什么

整个工具拆成两个**完全独立**的部分:

| 部分 | 解决问题 | 代码位置 |
|---|---|---|
| **OTP 自动化** | 在专用服务器上 7×24 维持 BUPT aTrust VPN 登录态。工作站微信里点一下 `netaccount.bupt.edu.cn` 链接抓 cookie,服务器端拿这个 cookie 轮询 `/otp` 拿 6 位 TOTP,然后操控 aTrust GUI 自动登录。 | `local/`, `server/`, `shared/`, `run_a.sh`, `run_b.sh` |
| **访问网关** | 从工作站访问只能经 VPN 才到达的 BUPT 内网 HTTP / HTTPS 站点和 SSH 主机。 | `gateway/` |

两半之间**没有代码依赖**。手动登录 aTrust 后单跑 gateway 也行,只跑 OTP
自动化不开 gateway 也行。

#### 为什么需要这个项目

BUPT 的 aTrust VPN 认证链是:(a) 微信侧 WeCom 绑定 → (b) 在
`netaccount.bupt.edu.cn` 上拿到浏览器 session cookie → (c) 每 30 秒
从 `/otp` 拿 TOTP → (d) 输入到桌面 aTrust 客户端。(a)+(b) 没法脚本化
(SSO 绑定锁在 WeChat 控制流里);(c)+(d) 可以。本项目把这条断链
接起来:让桌面 aTrust 长驻在一台服务器上,session 过期时自动重新
认证,完全不需要手工敲 TOTP。

### 架构

```
  工作站 (A)                                  服务器 (B)
  ═══════════                                 ═══════════
                                              ┌──────────────────────────┐
  bash run_a.sh ◀────── A↔B TLS 链 ─────────▶ │  run_b.sh + atrust_setup │
   ├─ mitm_capture.py    cookie + 刷新通知    │   - 操控 aTrust UI       │
   └─ mitmproxy addon    走 _link.py (mTLS)   │   - 连通性 keepalive     │
       (一次性抓微信侧                        │   - 掉线自动重登         │
        /otp cookie)                          │  otp_poller.py           │
                                              │   - 用 cookie 每 ~30s    │
                                              │     轮询 /otp            │
                                              │   - 本地把 OTP 喂给      │
                                              │     atrust_setup         │
                                              └──────────────────────────┘
                                                              ▲
                                                              │ aTrust VPN 隧道
                                                              ▼
                                              ╔══════════════════════════╗
                                              ║          内网            ║
                                              ║  (你的机构网络)          ║
  浏览器 ──── HTTP/HTTPS ─────────────┐                                  ║
                                      │       ┌──────────────────────────╣
                       gateway/       ▼       │  gateway/server.py       ║
                       server.py   :80/:443──▶│   - HTTPS forward proxy  ║
                       (无需任何                   - /?url=<目标>        ║
                        客户端配置)                - 自签发 leaf 证书    ║
                                                                          ║
  VSCode / ssh ── TCP ── :<端口> ──────────────▶  gateway/tcp_forward.py ║
                                                   - 裸 TCP splice       ║
                                                   - --target host:port  ║
                                              ╚══════════════════════════╝
```

每个绿色方框都是独立 Python 进程,挂掉一个不影响其他。

### 前置条件

**工作站 A**(Windows):

- Python 3.10+,`pip install requests mitmproxy cryptography paramiko`
- Git Bash(跑 `bash run_*.sh`)
- WeChat(仅 OTP 自动化需要;在微信里点 captive-portal 链接就能抓 cookie)

**服务器 B**(Windows,A 能从网络访问到):

- Python 3.10+,`pip install requests cryptography pywinauto psutil mitmproxy`
- Sangfor aTrust 桌面客户端 装在
  `C:\Program Files (x86)\Sangfor\aTrust\aTrustTray\aTrustTray.exe`
- 真实的 aTrust VPN 账号
- 你自己选的入站 TCP 端口(默认 6000/6001 用于 A↔B,gateway 用 80/443,
  `tcp_forward.py` 用你指定的)。Windows 防火墙**和**云安全组都要开。

### 第一部分 — OTP 自动化

#### 运行原理

1. **A 的 `mitm_capture.py`** 进入 capture 模式。短暂把自己设成 HKCU
   系统代理并以 addon 启动 `mitmdump`。
2. 操作者在 A 上微信里点开 captive-portal 链接。WeChat 内嵌浏览器经
   代理发请求。
3. addon 抓走 `/otp` 首次请求的 `Cookie:` 头,送回 A 主进程,A 通过 mTLS
   链路转发给 B 的 `otp_poller.py`。
4. B 的 `otp_poller.py` 现在握有这个长连接 `requests.Session`,以约 30s
   的间隔(跟门户自己的 JS 完全一致)轮询 `/otp`,每次拿一个 6 位 TOTP
   及其剩余生命周期。
5. **`atrust_setup.py`** 在 B 上用 `pywinauto` 驱动 aTrust GUI:走 URL
   配置对话框、勾条款、敲用户名、敲 OTP(点登录前再向 B 验证一次新鲜
   度),侦测登录成功/失败。
6. 登录成功后进 keepalive 循环,探测你指定的内网 URL。若全失败则杀
   aTrust 重走整个流程。

#### 启动命令

```bash
# B 服务器:
bash run_b.sh \
    --port <B监听端口> \
    --peer-port <A监听端口> --peer-host <A可达地址> \
    --target-host <你机构的 captive-portal 主机名> \
    --vpn-url     <你机构的 aTrust 门户 URL>
```

```bash
# A 工作站:
bash run_a.sh \
    --port <A监听端口> \
    --peer-port <B监听端口> --peer-host <B可达地址> \
    --target-host <同上,必须和 B 一致>
```

参数对照表:

| 参数 | 含义 | BUPT 默认 |
|---|---|---|
| `--port N` | 本机监听端口(TLS 链路本端) | — |
| `--peer-port N` | 对端监听端口(我们拨号过去的) | — |
| `--peer-host H` | 对端可达地址 | — |
| `--target-host H` | captive-portal 主机名,要轮询的 `/otp` 在这上面。**A 和 B 必须填一样**。 | `netaccount.bupt.edu.cn` |
| `--vpn-url U` | aTrust 门户 URL(在"接入地址"输入框里填的值)。仅 B 用。 | `https://vpn.bupt.edu.cn` |

`run_b.sh` 还支持 `takeover` / `stop` / `status` 子命令。
`Ctrl+B` 把 worker 转入后台,`Ctrl+C` 整体关停。

#### 其他启动器

- `run_test_local.sh` — A + B + setup 在同一台机器上的集成测试,
  不点最后的"登录",安全。
- `run_test_seperate.sh` — 只跑 B 端的测试。配合 A 端真实 `run_a.sh`
  使用。

#### keepalive 探测 URL

`atrust_setup.py` 默认探测一组 BUPT 校园站点(`cwxt.bupt.edu.cn` /
`tv.byr.cn` / `my.bupt.edu.cn` / `software.bupt.edu.cn` /
`zzgz.bupt.edu.cn`)— 选这一组是为了多样性,避免某个单系统短暂故障
被误判成"VPN 掉线"。换其他机构则用 `--keepalive-url URL`(可重复),
或直接编辑 `server/atrust_setup.py` 顶部的 `KEEPALIVE_URLS` 常量:

```bash
python C:/work/server/atrust_setup.py \
    --url <你的 aTrust 门户 URL> \
    --keepalive-url http://intranet1.example.org/ \
    --keepalive-url http://intranet2.example.org/login
```

`run_b.sh` **不**自动转发 `--keepalive-url`,你直接改常量或单独跑
`atrust_setup.py`。

### 第二部分 — 访问网关

#### `gateway/server.py` — HTTPS URL 转发 API

服务器上监听 80(HTTP)+ 443(HTTPS)。每个请求 URL 带 `?url=<目标>`
查询参数,网关在服务器端(经 aTrust 隧道)取回那个目标,原样把响应
回给客户端(状态码 / 响应头 / body 都不动)。

浏览器用法:

    https://<SERVER>/?url=https://intranet.example.org/some/path

目标 URL 内若含 `?`、`&`、`#`,记得 URL-encode。

子资源解析有三级,所以代理页面里相对 URL(CSS / 字体 / AJAX 等)
仍走 gateway:

1. 当次请求显式带 `?url=...`
2. `Referer` 含 `?url=...`(HTML 里的相对链接)
3. 上次响应 set 的 `__gw_origin` cookie(CSS 引用的字体/图片,其
   Referer 是 CSS 文件本身)

3xx 响应的绝对 `Location:` 头会被重写,保证浏览器留在 gateway 上。

##### 启动

```bash
python C:/work/gateway/server.py \
    [--http-port 80] [--https-port 443] \
    [--public-host <证书 SAN 主机名或 IP>]
```

`--public-host` 只影响首次启动生成的自签证书的 SAN(存在
`%APPDATA%\atrust-vpn\certs\gateway.{crt,key}`)。证书是自签的,
浏览器会警告 — 点继续访问即可。网关到上游是它**自己**用 Python ssl
做的真实 TLS 握手,所以警告只针对"你浏览器 ↔ 网关"这一段,跟目标
站点没关系。

##### 局限

- 网关本身**无鉴权**。任何能连到 80/443 的人都能用。靠防火墙 / 云
  安全组限制源 IP。
- HTML body 内的"绝对 URL"指向上游域名的链接不会重写。点这种链接
  浏览器会直接去内网域名,在工作站这边会失败。**完全相对路径**的现代
  Web app 工作良好。
- WebSocket / SSE / chunked 流是先缓冲整 body 再回。

#### `gateway/tcp_forward.py` — 裸 TCP 端口转发

简单的双向 TCP splice。适合非 TLS 协议(SSH / FTP control / MySQL
等),应用层不关心 TLS inspection。

```bash
python C:/work/gateway/tcp_forward.py \
    --listen-port <N> --target <内网主机>:22
```

之后工作站:

```bash
ssh -p <N> user@<SERVER>     # 等价于 ssh user@<内网主机>
```

**VSCode Remote-SSH** 建议把 `~/.ssh/config` 里的 **alias** 用成
VSCode 已经知道是 Linux 的内网主机名:

```
Host <内网主机别名>
    HostName <SERVER>
    Port <N>
    User <user>
```

VSCode 里连 `<内网主机别名>`。**别**直接用服务器 IP 连 — VSCode
会去 `remotePlatform` 表里查那个 IP 的平台(很可能是 Windows),
然后在 Linux 目标上尝试启动 `powershell`。

### 数据目录

运行时持久状态都在 `%APPDATA%\atrust-vpn\`(Windows)或
`~/.atrust-vpn/`(POSIX),**不在**源代码目录里:

```
%APPDATA%\atrust-vpn\
├── certs\
│   ├── link.crt + link.key       — A↔B mTLS(两端必须同一对)
│   ├── local.crt + local.key     — B↔setup 回环通道(只在 B)
│   └── gateway.crt + gateway.key — gateway HTTPS 自签证书(只在 B)
├── logs\
│   ├── a.log b.log setup.log mitm.log gateway.log tcp_forward.log
└── state\
    ├── *.pid                     — runner 进程的 PID 文件
    ├── capture.flag              — mitm 捕获模式标志
    └── proxy_backup.json         — 退出时恢复用
```

设 `ATRUST_VPN_DATA` 环境变量可改这个基础路径。

### 操作小贴士

- **B 端首次部署**:`run_b.sh` 首次启动会生成 `link.crt + link.key`。
  把这一对拷到 A 同样路径(`%APPDATA%\atrust-vpn\certs\`)。A 缺这对
  会大声报错。
- **mitmproxy CA on A**:`run_a.sh` 自动把 `mitmproxy-ca.cer` 安装到
  当前用户的"受信任的根证书颁发机构"(已装过则静默)。cookie 抓取的
  mitmdump 一步需要它。
- **后台 / 重新接管**:`Ctrl+B` 后台,`bash run_b.sh takeover` 重新接管。
- **完全停止**:`bash run_b.sh stop`(或 `run_a.sh stop`)。
  `_runner.sh` 也会清掉之前异常退出留下的 `tail` / `awk` 孤儿进程。

### 文件清单

```
bupt-netaccount-transfer-service/
├── LICENSE                         MIT 许可证
├── README.md                       本文件(双语,通过 <details> 折叠切换)
├── CHANGELOG.md                    Keep-a-Changelog 格式的版本说明
├── pyproject.toml                  PEP 621 项目元数据 + 依赖
├── _paths.sh                       shared/_paths.py 的 shell 镜像
├── run_a.sh                        A 端启动器
├── run_b.sh                        B 端启动器(otp_poller + atrust_setup)
├── run_test_local.sh               本机 A + B + setup 集成测试
├── run_test_seperate.sh            仅 B 端测试
├── local/
│   ├── mitm_capture.py             A: cookie 捕获编排
│   └── _otp_addon.py               A: mitmdump 插件,嗅 /otp 并提取账号 ID
├── server/
│   ├── otp_poller.py               B: /otp 轮询守护进程
│   ├── atrust_setup.py             B: aTrust UI 驱动 + keepalive
│   └── record_popup.py             B: 被动 UIA 事件录像工具(调试用)
├── shared/
│   ├── _paths.py / _paths.sh       运行时路径解析器
│   ├── _link.py                    mTLS 工具(证书生成 + send/serve)
│   ├── _spawn.py                   Windows detach 进程 spawn
│   ├── _runner.sh                  worker 注册 / attach / kill_all
│   └── _env.ps1                    HKCU 代理备份-还原 + kill_all
└── gateway/
    ├── server.py                   HTTPS URL 转发 API
    └── tcp_forward.py              裸 TCP 端口转发
```

### 参与贡献 & 社区

PR、issue、提问 **都欢迎** — 这是个小而专注的项目,正是那种最受
益于外部视角和真实部署反馈的项目。

- **发现 bug?** 开 issue,贴上复现步骤 + 相关日志(`a.log` /
  `b.log` / `setup.log` / `gateway.log`)。
- **有疑问?** GitHub Issues / Discussions 都可以,**问题不嫌小**。
- **想加新功能?** 先开 issue 讨论设计,再发 PR。
- **改造给非 BUPT 机构用?** 欢迎分享你最终用的
  `--target-host` / `--vpn-url` / `--keepalive-url`,对处境相似的
  其他人有参考价值。
- **fork 出你自己的版本?** 鼓励!代码小而精,故意没用重型框架,
  应该容易读、容易改、容易做成你自己的样子。

PR 风格建议:

- 一个 commit 一件事。
- 保持现有模块边界:`local/`(A 侧)/ `server/`(B 侧)/ `shared/` /
  `gateway/` 之间不要互相 import,除非走 `shared/`。
- **任何情况都不要 commit 个人凭据、服务器 IP、账号 ID 或运营
  机密** — 注释、示例输出都不行,用现有 CLI 参数表达。
- 测试入口在 `run_test_local.sh` / `run_test_seperate.sh`,请保持
  它们能通过。

项目的长期健康依赖**真实使用 + 边界场景反馈 + 把经验回馈进来**。
如果你有一套可用的部署,哪怕只在 issue 里写一句话,都对项目有帮助。

### 许可证

MIT — 见 [LICENSE](LICENSE)。

</details>
