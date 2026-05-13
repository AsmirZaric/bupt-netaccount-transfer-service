"""Module A: WeChat-side mitmproxy capture orchestrator.

Part of bupt-netaccount-transfer-service — purpose-built for the
captive-portal TOTP flow at BUPT's netaccount portal
(netaccount.bupt.edu.cn). On any other institution that uses a similar
"cookie + /otp poll" pattern you can re-target via --target-host, but
this file's design assumptions (homepage student-ID parsing, /otp
cadence matching the portal's own JS) reflect what BUPT does.

Runs alongside Module B (otp_poller.py). Lifecycle:

  Phase                     | Proxy | mitmdump | addon flag
  --------------------------|-------|----------|-----------
  Bootstrap capture         | ON    | running  | present
  Steady-state (idle)       | OFF   | killed   | absent
  Refresh capture (B failed)| ON    | running  | present

mitmdump is **only alive during the active capture window** (typically
seconds). The rest of the time the system proxy is restored to the user's
original state and no mitmdump process exists.

Communication:
  - Addon -> A: HTTP POST 127.0.0.1:9999/cookies (loopback callback)
  - A -> B   : TLS message to 127.0.0.1:6001     (deliver Cookie header)
  - B -> A   : TLS message to 127.0.0.1:6000     ({"type":"refresh_needed"})
"""

from __future__ import annotations

import os
import sys
# Add sibling `shared/` to sys.path so `_paths` / `_link` resolve no
# matter which cwd we're launched from. Must precede the first
# `import _paths` (which happens lower in this file's header).
_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared')
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import argparse
import atexit
import ctypes
import http.server
import json
import logging
import re
import signal
import subprocess
import threading
import time
import urllib.parse
import winreg

import _link

PROXY_PORT = 18080
CALLBACK_PORT = 9999
# Inter-module link. A listens for B->A messages on LISTEN_HOST:LISTEN_PORT;
# A sends A->B messages to PEER_HOST:PEER_PORT. All four are CLI flags so
# A and B can be deployed on separate hosts. Defaults shown below are the
# loopback-test values (run_test_local.sh leaves the flags unspecified).
DEFAULT_LISTEN_HOST = '127.0.0.1'
DEFAULT_LISTEN_PORT = 6000
DEFAULT_PEER_HOST   = '127.0.0.1'
DEFAULT_PEER_PORT   = 6001
# Populated by main() from argv before any listener / send call references
# them. _on_b_message / _send_cookie_to_b read these.
LISTEN_HOST_A: str = DEFAULT_LISTEN_HOST
LISTEN_PORT_A: int = DEFAULT_LISTEN_PORT
PEER_HOST_B:   str = DEFAULT_PEER_HOST
PEER_PORT_B:   int = DEFAULT_PEER_PORT
# Hostname of the captive portal whose /otp endpoint we're capturing.
# Default value targets BUPT's netaccount portal — this project exists
# specifically for that captive portal's TOTP flow. Override via
# --target-host if you're adapting this to another institution.
DEFAULT_TARGET_HOST = 'netaccount.bupt.edu.cn'
TARGET_HOST: str = DEFAULT_TARGET_HOST

import _paths

HERE = os.path.dirname(os.path.abspath(__file__))
ADDON_PATH = os.path.join(HERE, '_otp_addon.py')
CAPTURE_FLAG = _paths.CAPTURE_FLAG
PROXY_BACKUP = _paths.PROXY_BACKUP
MITM_LOG = _paths.LOG_MITM

# HKCU Internet Settings
_REG_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d [A %(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S',
)
log = logging.getLogger('A')


# ---------------------------------------------------------------------------
# HKCU proxy management (native, no PowerShell)
# ---------------------------------------------------------------------------

def _wininet_notify() -> None:
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


def _proxy_set_native() -> None:
    cur = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_KEY, 0, winreg.KEY_READ) as k:
        for name in ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL'):
            try:
                v, _kind = winreg.QueryValueEx(k, name)
                cur[name] = v
            except FileNotFoundError:
                cur[name] = ''
    already_ours = cur.get('ProxyEnable') == 1 and cur.get('ProxyServer') == f'127.0.0.1:{PROXY_PORT}'
    if not already_ours:
        _paths.ensure_dirs()
        with open(PROXY_BACKUP, 'w', encoding='utf-8') as fh:
            json.dump(cur, fh)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, 'ProxyEnable',   0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, 'ProxyServer',   0, winreg.REG_SZ,    f'127.0.0.1:{PROXY_PORT}')
        winreg.SetValueEx(k, 'ProxyOverride', 0, winreg.REG_SZ,    '<local>')
        winreg.SetValueEx(k, 'AutoConfigURL', 0, winreg.REG_SZ,    '')
    _wininet_notify()


def _proxy_restore_native() -> None:
    backup = None
    if os.path.exists(PROXY_BACKUP):
        try:
            with open(PROXY_BACKUP, 'r', encoding='utf-8') as fh:
                backup = json.load(fh)
        except Exception:
            backup = None
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if backup:
            winreg.SetValueEx(k, 'ProxyEnable',   0, winreg.REG_DWORD,
                              int(backup.get('ProxyEnable', 0)))
            winreg.SetValueEx(k, 'ProxyServer',   0, winreg.REG_SZ,
                              str(backup.get('ProxyServer', '')))
            winreg.SetValueEx(k, 'ProxyOverride', 0, winreg.REG_SZ,
                              str(backup.get('ProxyOverride', '')))
            winreg.SetValueEx(k, 'AutoConfigURL', 0, winreg.REG_SZ,
                              str(backup.get('AutoConfigURL', '')))
        else:
            winreg.SetValueEx(k, 'ProxyEnable',   0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(k, 'AutoConfigURL', 0, winreg.REG_SZ,    '')
    _wininet_notify()


# ---------------------------------------------------------------------------
# Capture flag (shared with mitm addon)
# ---------------------------------------------------------------------------

def _flag_set() -> None:
    _paths.ensure_dirs()
    with open(CAPTURE_FLAG, 'w') as fh:
        fh.write(str(time.time()))


def _flag_clear() -> None:
    try:
        os.unlink(CAPTURE_FLAG)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Mitmdump subprocess
# ---------------------------------------------------------------------------

def _spawn_mitmdump() -> subprocess.Popen:
    _paths.ensure_dirs()
    fh = open(MITM_LOG, 'w', encoding='utf-8', errors='replace', buffering=1)
    # Pass-through (no TLS interception) for everything except the
    # captive-portal host the addon cares about. Other apps' HTTPS
    # traffic is not intercepted, decrypted, or rewritten.
    target_re = re.escape(TARGET_HOST)
    ignore_re = rf'^(?!{target_re}(:\d+)?$).*'
    child_env = os.environ.copy()
    # The addon reads this to scope its hooks to the right host.
    child_env['MITM_TARGET_HOST'] = TARGET_HOST
    return subprocess.Popen(
        [
            'mitmdump',
            '-s', ADDON_PATH,
            '--listen-port', str(PROXY_PORT),
            '--set', 'termlog_verbosity=info',
            '--no-http2',
            '--ignore-hosts', ignore_re,
        ],
        stdout=fh,
        stderr=subprocess.STDOUT,
        cwd=HERE,
        env=child_env,
    )


def _wait_until_listen(port: int, timeout: float = 8.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect(('127.0.0.1', port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


def _kill_mitmdump(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Win32 helpers
# ---------------------------------------------------------------------------

def _show_alert(text: str, title: str = 'otp-capture') -> None:
    """Pop a system MessageBox in a background thread (non-blocking)."""
    def _show():
        MB_OK = 0
        MB_ICONWARNING = 0x30
        MB_TOPMOST = 0x40000
        MB_SETFOREGROUND = 0x10000
        try:
            ctypes.windll.user32.MessageBoxW(
                0, text, title,
                MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND,
            )
        except Exception as e:
            log.error('MessageBox failed: %s', e)
    threading.Thread(target=_show, daemon=True).start()


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _hwnd_owner_image(hwnd) -> str:
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    h = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not h:
        return ''
    try:
        buf = ctypes.create_unicode_buffer(260)
        size = ctypes.c_ulong(260)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value).lower()
        return ''
    finally:
        kernel32.CloseHandle(h)


def _wm_close_wechat_browser() -> int:
    """PostMessage WM_CLOSE to visible Chrome_WidgetWin* windows owned by
    WeChatAppEx.exe (the embedded captive-portal tab). Doesn't touch Weixin main UI."""
    user32 = ctypes.windll.user32
    closed = [0]

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def _enum(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        cls = ctypes.create_unicode_buffer(64)
        user32.GetClassNameW(hwnd, cls, 64)
        if 'Chrome_WidgetWin' not in cls.value:
            return True
        if _hwnd_owner_image(hwnd) != 'wechatappex.exe':
            return True
        ttl = ctypes.create_unicode_buffer(128)
        user32.GetWindowTextW(hwnd, ttl, 128)
        log.info('  WM_CLOSE cls=%s title=%r', cls.value, ttl.value[:40])
        user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        closed[0] += 1
        return True

    user32.EnumWindows(_enum, None)
    return closed[0]


# ---------------------------------------------------------------------------
# Module A state + capture lifecycle
# ---------------------------------------------------------------------------

class State:
    """Mutable shared state for callback + listener threads."""

    def __init__(self) -> None:
        self.cookie_event = threading.Event()
        self.cookie_header: str = ''
        self.username: str = ''  # extracted by addon from / HTML
        self.shutting_down = False
        # Holds the live mitmdump Popen handle when in capture mode; None
        # when in idle / pass-through state.
        self.mitm: subprocess.Popen | None = None
        # Coarse lock so bootstrap and a refresh request don't both try to
        # spin up mitmdump simultaneously.
        self.capture_lock = threading.Lock()


def _enter_capture(state: State) -> bool:
    """Enable system proxy, spawn mitmdump, arm capture flag.

    Returns True on success. Idempotent under lock: a second call while
    already in capture mode is a no-op.
    """
    with state.capture_lock:
        if state.mitm is not None:
            log.info('already in capture mode -- no-op')
            return True
        log.info('--> enter capture mode (proxy on, mitmdump up, flag armed)')
        try:
            _proxy_set_native()
        except Exception as e:
            log.error('proxy_set_native failed: %s', e)
            return False
        proc = _spawn_mitmdump()
        if not _wait_until_listen(PROXY_PORT, timeout=8):
            log.error('mitmdump failed to listen on %d', PROXY_PORT)
            _kill_mitmdump(proc)
            try:
                _proxy_restore_native()
            except Exception:
                pass
            return False
        state.mitm = proc
        _flag_set()
        return True


def _exit_capture(state: State) -> None:
    """Kill mitmdump, restore system proxy, clear capture flag.

    Order matters: clear flag → restore proxy (so apps stop using mitm)
    → kill mitmdump (now safe to die without leaving Chromium hanging)."""
    with state.capture_lock:
        log.info('<-- exit capture mode (flag cleared, proxy restored, mitmdump killed)')
        _flag_clear()
        try:
            _proxy_restore_native()
        except Exception as e:
            log.error('proxy_restore_native failed: %s', e)
        _kill_mitmdump(state.mitm)
        state.mitm = None


# ---------------------------------------------------------------------------
# HTTP callback server (addon -> A) on port 9999
# ---------------------------------------------------------------------------

def _make_callback_handler(state: State):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            n = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(n).decode('utf-8', 'replace')
            if self.path == '/cookies':
                qs = urllib.parse.parse_qs(body, keep_blank_values=True)
                state.cookie_header = qs.get('cookie', [''])[0]
                state.username = qs.get('username', [''])[0]
                state.cookie_event.set()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')
            else:
                self.send_response(404)
                self.end_headers()

    return H


def _start_callback_server(state: State) -> http.server.HTTPServer:
    srv = http.server.ThreadingHTTPServer(
        ('127.0.0.1', CALLBACK_PORT), _make_callback_handler(state),
    )
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------------------
# TLS link with Module B
# ---------------------------------------------------------------------------

def _send_cookie_to_b(cookie_header: str, username: str) -> bool:
    try:
        _link.send(PEER_HOST_B, PEER_PORT_B, {
            'type': 'cookie',
            'cookie_header': cookie_header,
            'username': username,
        })
        log.info('-> B (cookie len=%d, username=%s)', len(cookie_header),
                 username or '<unknown>')
        return True
    except Exception as e:
        log.error('failed to send cookie to B at %s:%d: %s',
                  PEER_HOST_B, PEER_PORT_B, e)
        return False


def _ping_b(timeout: float = 4.0) -> bool:
    """One-shot TLS hello to verify Module B is reachable + cert trust works."""
    try:
        _link.send(PEER_HOST_B, PEER_PORT_B,
                   {'type': 'hello', 'from': 'A'}, timeout=timeout)
        return True
    except Exception as e:
        log.error('B connectivity check failed (%s:%d): %s',
                  PEER_HOST_B, PEER_PORT_B, e)
        return False


def _on_b_message(state: State, msg: dict) -> None:
    """Handle messages received from Module B on port 6000."""
    mtype = msg.get('type', '')
    if mtype == 'refresh_needed':
        reason = msg.get('reason', '')
        log.warning('<- B refresh_needed (reason=%s)', reason)
        # Re-enter capture mode and prompt the user.
        if not _enter_capture(state):
            log.error('failed to enter capture mode for refresh')
            return
        state.cookie_event.clear()
        _show_alert(
            'OTP 会话失效，请在 WeChat 中重新点击 OTP 链接。\n'
            '点击后本程序会自动捕获新的 cookie 并恢复轮询。',
            'otp-capture 需要刷新',
        )
        # Wait for the next /otp cookie capture in a background thread so we
        # don't block the TLS server.
        threading.Thread(
            target=_handle_capture_cycle, args=(state,), daemon=True,
        ).start()
    elif mtype == 'hello':
        log.info('<- B hello')
    else:
        log.warning('<- B unknown msg: %s', msg)


def _handle_capture_cycle(state: State) -> None:
    """Block until addon delivers a fresh Cookie, send it to B, exit capture."""
    if not state.cookie_event.wait(timeout=300):
        log.error('refresh capture timed out (300s)')
        _exit_capture(state)
        return
    cookie = state.cookie_header
    username = state.username
    state.cookie_event.clear()
    sent = _send_cookie_to_b(cookie, username)
    _exit_capture(state)
    threading.Thread(target=_wm_close_wechat_browser, daemon=True).start()
    if sent:
        log.info('refresh delivered; back to idle')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Module A: mitm capture + TLS link')
    p.add_argument('--listen-host', default=DEFAULT_LISTEN_HOST,
                   help=f'A listener bind interface (default {DEFAULT_LISTEN_HOST})')
    p.add_argument('--listen-port', type=int, default=DEFAULT_LISTEN_PORT,
                   help=f'A listener port for B->A messages (default {DEFAULT_LISTEN_PORT})')
    p.add_argument('--peer-host', default=DEFAULT_PEER_HOST,
                   help=f'B host to dial for A->B messages (default {DEFAULT_PEER_HOST})')
    p.add_argument('--peer-port', type=int, default=DEFAULT_PEER_PORT,
                   help=f'B port to dial for A->B messages (default {DEFAULT_PEER_PORT})')
    p.add_argument('--target-host', default=DEFAULT_TARGET_HOST,
                   help='captive-portal hostname whose /otp endpoint is '
                        'being captured. MUST be set to match your '
                        f'institution. Default: {DEFAULT_TARGET_HOST}')
    return p.parse_args(argv)


def main() -> int:
    args = _parse_args()
    global LISTEN_HOST_A, LISTEN_PORT_A, PEER_HOST_B, PEER_PORT_B, TARGET_HOST
    LISTEN_HOST_A = args.listen_host
    LISTEN_PORT_A = args.listen_port
    PEER_HOST_B   = args.peer_host
    PEER_PORT_B   = args.peer_port
    TARGET_HOST   = args.target_host

    state = State()
    cleaned = [False]

    def cleanup() -> None:
        if cleaned[0]:
            return
        cleaned[0] = True
        log.info('cleanup')
        _exit_capture(state)

    def on_signal(*_):
        cleanup()
        sys.exit(130)

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, on_signal)
    atexit.register(cleanup)

    log.info('preparing TLS link cert')
    _link.ensure_cert()

    log.info('peer B at %s:%d', PEER_HOST_B, PEER_PORT_B)
    log.info('checking connectivity to B ...')
    if not _ping_b():
        msg = (
            f'无法连接到 Module B（{PEER_HOST_B}:{PEER_PORT_B}）。\n\n'
            '请检查：\n'
            f'  1. B 端的 otp_poller.py 已经启动并监听 {PEER_PORT_B} 端口\n'
            f'  2. {PEER_HOST_B} 这个地址从本机可达（防火墙 / 网络）\n'
            '  3. link.crt / link.key 已从 B 端复制到 A 端 '
            '(DATA_DIR/certs, 同一对密钥)\n\n'
            '解决后请重启本程序。'
        )
        log.error(msg.replace('\n', ' | '))
        _show_alert(msg, 'otp-capture 无法连接 B')
        # Give the alert thread a moment so the user actually sees the popup
        # before the process exits.
        time.sleep(2)
        return 1
    log.info('B reachable')

    log.info('starting addon callback server on 127.0.0.1:%d', CALLBACK_PORT)
    _start_callback_server(state)

    log.info('starting TLS server (B -> A) on %s:%d', LISTEN_HOST_A, LISTEN_PORT_A)
    threading.Thread(
        target=_link.serve,
        args=(LISTEN_PORT_A, lambda m: _on_b_message(state, m), LISTEN_HOST_A),
        daemon=True,
    ).start()

    # Bootstrap capture: spin mitmdump up only for this window.
    if not _enter_capture(state):
        return 1

    log.info('=' * 60)
    log.info('  TRIGGER NOW: open the OTP link in WeChat')
    log.info('  (waiting up to 120s for the first /otp request)')
    log.info('=' * 60)
    # Pop a system MessageBox in addition to the log line so the user gets
    # the bootstrap prompt even when running in detached / service mode where
    # stdout is redirected to a log file.
    _show_alert(
        '请在 WeChat 中点击 OTP 链接以初始化 OTP 服务。\n'
        '点击后本程序会自动捕获 cookie 并把轮询交给 otp_poller。',
        'otp-capture 初始化',
    )

    if not state.cookie_event.wait(120):
        log.error('TIMEOUT -- no /otp captured in 120s; see %s', MITM_LOG)
        _exit_capture(state)
        return 1

    cookie = state.cookie_header
    username = state.username
    state.cookie_event.clear()
    log.info('captured Cookie header (len=%d, username=%s) -> sending to B',
             len(cookie), username or '<unknown>')
    sent = _send_cookie_to_b(cookie, username)
    _exit_capture(state)
    threading.Thread(target=_wm_close_wechat_browser, daemon=True).start()
    if not sent:
        log.error('initial cookie delivery failed; is otp_poller.py running?')
        return 1

    log.info('=' * 60)
    log.info('  bootstrapped. Module A is now IDLE in pass-through mode.')
    log.info('  mitmdump is terminated; system proxy restored.')
    log.info('  Will re-spin mitmdump only if Module B reports failure.')
    log.info('  (Ctrl+C to stop)')
    log.info('=' * 60)

    try:
        while not state.shutting_down:
            time.sleep(60)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(130)
