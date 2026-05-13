# bupt-netaccount-transfer-service

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](#%E5%89%8D%E7%BD%AE%E6%9D%A1%E4%BB%B6)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#%E5%89%8D%E7%BD%AE%E6%9D%A1%E4%BB%B6)
[![Target: BUPT aTrust](https://img.shields.io/badge/target-BUPT%20aTrust%20VPN-c8102e.svg)](#)

[English](README.md) | **中文**

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

---

## 它解决什么

整个工具拆成两个**完全独立**的部分:

| 部分 | 解决问题 | 代码位置 |
|---|---|---|
| **OTP 自动化** | 在专用服务器上 7×24 维持 BUPT aTrust VPN 登录态。工作站微信里点一下 `netaccount.bupt.edu.cn` 链接抓 cookie,服务器端拿这个 cookie 轮询 `/otp` 拿 6 位 TOTP,然后操控 aTrust GUI 自动登录。 | `local/`, `server/`, `shared/`, `run_a.sh`, `run_b.sh` |
| **访问网关** | 从工作站访问只能经 VPN 才到达的 BUPT 内网 HTTP / HTTPS 站点和 SSH 主机。 | `gateway/` |

两半之间**没有代码依赖**。手动登录 aTrust 后单跑 gateway 也行,只跑 OTP
自动化不开 gateway 也行。

### 为什么需要这个项目

BUPT 的 aTrust VPN 认证链是:(a) 微信侧 WeCom 绑定 → (b) 在
`netaccount.bupt.edu.cn` 上拿到浏览器 session cookie → (c) 每 30 秒
从 `/otp` 拿 TOTP → (d) 输入到桌面 aTrust 客户端。(a)+(b) 没法脚本化
(SSO 绑定锁在 WeChat 控制流里);(c)+(d) 可以。本项目把这条断链
接起来:让桌面 aTrust 长驻在一台服务器上,session 过期时自动重新
认证,完全不需要手工敲 TOTP。

---

## 架构

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

---

## 前置条件

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

---

## 第一部分 — OTP 自动化

### 运行原理

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

### 启动命令

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

### 其他启动器

- `run_test_local.sh` — A + B + setup 在同一台机器上的集成测试,
  不点最后的"登录",安全。
- `run_test_seperate.sh` — 只跑 B 端的测试。配合 A 端真实 `run_a.sh`
  使用。

### keepalive 探测 URL

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

---

## 第二部分 — 访问网关

### `gateway/server.py` — HTTPS URL 转发 API

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

#### 启动

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

#### 局限

- 网关本身**无鉴权**。任何能连到 80/443 的人都能用。靠防火墙 / 云
  安全组限制源 IP。
- HTML body 内的"绝对 URL"指向上游域名的链接不会重写。点这种链接
  浏览器会直接去内网域名,在工作站这边会失败。**完全相对路径**的现代
  Web app 工作良好。
- WebSocket / SSE / chunked 流是先缓冲整 body 再回。

### `gateway/tcp_forward.py` — 裸 TCP 端口转发

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

---

## 数据目录

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

---

## 操作小贴士

- **B 端首次部署**:`run_b.sh` 首次启动会生成 `link.crt + link.key`。
  把这一对拷到 A 同样路径(`%APPDATA%\atrust-vpn\certs\`)。A 缺这对
  会大声报错。
- **mitmproxy CA on A**:`run_a.sh` 自动把 `mitmproxy-ca.cer` 安装到
  当前用户的"受信任的根证书颁发机构"(已装过则静默)。cookie 抓取的
  mitmdump 一步需要它。
- **后台 / 重新接管**:`Ctrl+B` 后台,`bash run_b.sh takeover` 重新接管。
- **完全停止**:`bash run_b.sh stop`(或 `run_a.sh stop`)。
  `_runner.sh` 也会清掉之前异常退出留下的 `tail` / `awk` 孤儿进程。

---

## 文件清单

```
bupt-netaccount-transfer-service/
├── LICENSE                         MIT 许可证
├── README.md                       英文文档
├── README.zh-CN.md                 本文档
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

---

## 参与贡献 & 社区

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

## 许可证

MIT — 见 [LICENSE](LICENSE)。
