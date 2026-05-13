"""Module B: external /otp polling daemon.

Part of bupt-netaccount-transfer-service — purpose-built for the BUPT
netaccount captive portal (https://netaccount.bupt.edu.cn/otp). The
cadence of `sleep expires_in + 2` matches what the portal's own
page-JS does; deviating from that pattern triggers session
invalidation.

Listens on TLS port 6001 for `cookie` messages from Module A. Owns the
long-running requests.Session that polls `https://<--target-host>/otp`
at the cadence the portal's own page-JS uses (sleep `expires_in + 2`
after each successful response).

When the polling loop hits a non-200 status (typically 401 / 419 / a 302 to
/auth/login -- session invalidated) it pushes one `refresh_needed` message
to Module A on TLS port 6000 and blocks until A delivers a fresh Cookie via
its TLS listener on 6001.

Setup channel (loopback only):
  In addition to the A<->B link, B starts a SECOND TLS listener bound to
  127.0.0.1:LOCAL_LISTEN_PORT (default 7001) so the colocated
  atrust_setup.py can ask for the latest OTP via a `get_otp` request. This
  channel uses an independent self-signed cert pair (_local.crt/_local.key)
  that NEVER leaves the B+setup host. Serial accept loop -> at most one
  setup subscriber is processed at a time.

Wire protocol:
  A    -> B (6001): {"type":"cookie", "cookie_header":"...", "username":"..."}
  B    -> A (6000): {"type":"refresh_needed", "reason":"..."}
  setup-> B (7001): {"type":"get_otp"}
  B    -> setup   : {"type":"otp_state", "has_otp":true, "username":...,
                                            "code":..., "period":...,
                                            "expires_in":..., "written_at":...}
                or {"type":"otp_state", "has_otp":false, "reason":"..."}
"""

from __future__ import annotations

import os
import sys
# Add sibling `shared/` to sys.path so `_paths` / `_link` resolve.
_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared')
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import argparse
import atexit
import logging
import signal
import threading
import time
import urllib.parse

import requests

import _link
import _paths

# Inter-module link. B listens for A->B messages on LISTEN_HOST:LISTEN_PORT;
# B sends refresh_needed messages to PEER_HOST:PEER_PORT. All four are CLI
# flags. Defaults shown below match run_test_local.sh's loopback wiring.
DEFAULT_LISTEN_HOST = '0.0.0.0'
DEFAULT_LISTEN_PORT = 6001
DEFAULT_PEER_HOST   = '127.0.0.1'
DEFAULT_PEER_PORT   = 6000
# Setup channel (B<->atrust_setup). ALWAYS loopback. --local-port may
# override the port; the host is hard-coded to 127.0.0.1.
LOCAL_LISTEN_HOST = '127.0.0.1'
DEFAULT_LOCAL_LISTEN_PORT = 7001
# Populated by main() from argv before any listener / send call references
# them.
LISTEN_HOST_B:    str = DEFAULT_LISTEN_HOST
LISTEN_PORT_B:    int = DEFAULT_LISTEN_PORT
PEER_HOST_A:      str = DEFAULT_PEER_HOST
PEER_PORT_A:      int = DEFAULT_PEER_PORT
LOCAL_LISTEN_PORT: int = DEFAULT_LOCAL_LISTEN_PORT
# Captive-portal hostname. Default targets BUPT's netaccount portal —
# this project exists specifically for that captive portal's TOTP flow.
# Override via --target-host when adapting to other institutions.
DEFAULT_TARGET_HOST = 'netaccount.bupt.edu.cn'
TARGET_HOST: str = DEFAULT_TARGET_HOST

WECHAT_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 '
    'NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) '
    'WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541934)'
)

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d [B %(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S',
)
log = logging.getLogger('B')


def _parse_cookie_header(header: str) -> list[tuple[str, str]]:
    out = []
    for part in header.split(';'):
        part = part.strip()
        if '=' in part:
            n, v = part.split('=', 1)
            out.append((n.strip(), v.strip()))
    return out


class State:
    def __init__(self) -> None:
        self.cookie_event = threading.Event()  # set when A delivers a cookie
        self.cookie_header: str = ''
        # Last captive-portal username (10-digit account ID) seen from A. Sticky:
        # if A re-sends with an empty username (e.g. addon couldn't parse the
        # homepage that round), keep the prior known value.
        self.username: str = ''
        self.lock = threading.Lock()
        self.shutting_down = False
        # Most recent successful /otp response, kept in memory ONLY (no disk
        # persistence). Cleared on refresh_needed / shutdown. setup reads it
        # via the 127.0.0.1:7001 TLS channel.
        #   shape: {'username','code','period','expires_in','written_at'}
        self.otp_cache: dict | None = None


def _build_session(cookie_header: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        'User-Agent': WECHAT_UA,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Referer': f'https://{TARGET_HOST}/',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
    })
    seen = set()
    for name, value in _parse_cookie_header(cookie_header):
        s.cookies.set(name, value, domain=TARGET_HOST, path='/')
        seen.add(name)
    if 'XSRF-TOKEN' not in seen or 'laravel_session' not in seen:
        log.warning('cookie missing required name. seen=%s', sorted(seen))
    return s


def _on_a_message(state: State, msg: dict) -> None:
    """Handle messages received from Module A on the listen port."""
    mtype = msg.get('type', '')
    if mtype == 'cookie':
        ch = msg.get('cookie_header', '')
        username = msg.get('username', '')
        log.info('<- A cookie (len=%d, username=%s)', len(ch), username or '<unknown>')
        with state.lock:
            state.cookie_header = ch
            # Update username only if a non-empty one was supplied -- avoid
            # stomping a known good value with an empty one.
            if username:
                if state.username and state.username != username:
                    log.warning('username changed: %s -> %s',
                                state.username, username)
                state.username = username
            state.cookie_event.set()
    elif mtype == 'hello':
        log.info('<- A hello (connectivity probe)')
    else:
        log.warning('<- A unknown msg: %s', msg)


def _send_refresh_to_a(reason: str) -> bool:
    try:
        _link.send(PEER_HOST_A, PEER_PORT_A,
                   {'type': 'refresh_needed', 'reason': reason})
        log.info('-> A refresh_needed (reason=%s)', reason)
        return True
    except Exception as e:
        log.error('failed to notify A at %s:%d: %s',
                  PEER_HOST_A, PEER_PORT_A, e)
        return False


def _on_setup_request(state: State, msg: dict) -> dict:
    """Handle a request on the loopback B<->setup TLS channel."""
    if not isinstance(msg, dict):
        return {'type': 'error', 'message': 'request must be a dict'}
    mtype = msg.get('type', '')
    if mtype == 'get_otp':
        with state.lock:
            cache = state.otp_cache
            uname = state.username
            has_cookie = state.cookie_event.is_set()
        if cache is None:
            if not has_cookie:
                reason = 'waiting_for_cookie'
            else:
                reason = 'polling_in_progress'
            return {'type': 'otp_state', 'has_otp': False,
                    'reason': reason, 'username': uname}
        # Return a snapshot copy so subsequent state mutations don't leak.
        return {'type': 'otp_state', 'has_otp': True, **cache}
    if mtype == 'ping':
        return {'type': 'pong'}
    return {'type': 'error', 'message': f'unknown request type: {mtype!r}'}


def _polling_loop(state: State) -> None:
    no_proxy = {'http': None, 'https': None}
    consecutive_net_errors = 0

    while not state.shutting_down:
        # Wait for a fresh cookie if none is loaded.
        if not state.cookie_event.is_set():
            log.info('waiting for Module A to deliver a Cookie ...')
            if not state.cookie_event.wait(timeout=600):
                log.warning('still waiting for Cookie after 600s')
                continue

        with state.lock:
            cookie_header = state.cookie_header

        s = _build_session(cookie_header)

        # Inner poll loop -- runs until the session breaks.
        while not state.shutting_down:
            xsrf = s.cookies.get('XSRF-TOKEN', domain=TARGET_HOST)
            if xsrf:
                s.headers['X-XSRF-TOKEN'] = urllib.parse.unquote(xsrf)

            try:
                r = s.get(
                    f'https://{TARGET_HOST}/otp',
                    allow_redirects=False,
                    timeout=10,
                    proxies=no_proxy,
                )
            except requests.RequestException as e:
                consecutive_net_errors += 1
                log.error('/otp network error #%d: %s', consecutive_net_errors, e)
                if consecutive_net_errors >= 3:
                    consecutive_net_errors = 0
                    state.cookie_event.clear()
                    with state.lock:
                        state.otp_cache = None
                    _send_refresh_to_a(f'network error: {e}')
                    break
                time.sleep(2)
                continue

            consecutive_net_errors = 0

            if r.status_code != 200:
                # Session no longer valid (typical: 302 to /auth/login, 401, 419).
                log.warning('/otp status=%d -- session likely invalid', r.status_code)
                state.cookie_event.clear()
                with state.lock:
                    state.otp_cache = None
                _send_refresh_to_a(f'status {r.status_code}')
                break

            try:
                data = r.json()
            except Exception:
                log.warning('/otp non-json: %s', r.text[:120])
                state.cookie_event.clear()
                with state.lock:
                    state.otp_cache = None
                _send_refresh_to_a('non-json response')
                break

            otp_code = data.get('code', '?')
            period = data.get('period', 30)
            expires_in = data.get('expires_in', 25)
            with state.lock:
                state.otp_cache = {
                    'username':   state.username,
                    'code':       otp_code,
                    'period':     period,
                    'expires_in': expires_in,
                    'written_at': time.time(),
                }
            log.info('OTP=%s  period=%ds  expires_in=%ds  user=%s',
                     otp_code, period, expires_in, state.username or '<unknown>')

            # Page-JS cadence: refresh `expires_in + 2` seconds after the response.
            sleep_s = max(1, expires_in + 2)
            for _ in range(sleep_s):
                if state.shutting_down:
                    return
                time.sleep(1)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Module B: /otp poller + TLS link')
    p.add_argument('--listen-host', default=DEFAULT_LISTEN_HOST,
                   help=f'B listener bind interface (default {DEFAULT_LISTEN_HOST})')
    p.add_argument('--listen-port', type=int, default=DEFAULT_LISTEN_PORT,
                   help=f'B listener port for A->B messages (default {DEFAULT_LISTEN_PORT})')
    p.add_argument('--peer-host', default=DEFAULT_PEER_HOST,
                   help=f'A host to dial for B->A messages (default {DEFAULT_PEER_HOST})')
    p.add_argument('--peer-port', type=int, default=DEFAULT_PEER_PORT,
                   help=f'A port to dial for B->A messages (default {DEFAULT_PEER_PORT})')
    p.add_argument('--local-port', type=int, default=DEFAULT_LOCAL_LISTEN_PORT,
                   help=f'B<->setup loopback port (default {DEFAULT_LOCAL_LISTEN_PORT})')
    p.add_argument('--target-host', default=DEFAULT_TARGET_HOST,
                   help='captive-portal hostname whose /otp endpoint to '
                        'poll. MUST be set to match your institution. '
                        f'Default: {DEFAULT_TARGET_HOST}')
    return p.parse_args(argv)


def main() -> int:
    args = _parse_args()
    global LISTEN_HOST_B, LISTEN_PORT_B, PEER_HOST_A, PEER_PORT_A, LOCAL_LISTEN_PORT, TARGET_HOST
    LISTEN_HOST_B     = args.listen_host
    LISTEN_PORT_B     = args.listen_port
    PEER_HOST_A       = args.peer_host
    PEER_PORT_A       = args.peer_port
    LOCAL_LISTEN_PORT = args.local_port
    TARGET_HOST       = args.target_host

    state = State()

    def _clear_cache_on_exit():
        # Defensive: ensure no in-memory OTP outlives the process. Cache is
        # not on disk anyway; this is for symmetry with refresh_needed.
        try:
            with state.lock:
                state.otp_cache = None
        except Exception:
            pass

    atexit.register(_clear_cache_on_exit)

    def on_signal(*_):
        state.shutting_down = True
        _clear_cache_on_exit()
        sys.exit(130)

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, on_signal)

    # Pre-generate both cert pairs (idempotent).
    #   _link.crt / _link.key: A<->B (must be copied to A side)
    #   _local.crt / _local.key: B<->setup (NEVER copy off this host)
    _link.ensure_cert()
    _link.ensure_local_cert()

    log.info('peer A at %s:%d', PEER_HOST_A, PEER_PORT_A)
    log.info('starting TLS server (A -> B) on %s:%d', LISTEN_HOST_B, LISTEN_PORT_B)
    threading.Thread(
        target=_link.serve,
        args=(LISTEN_PORT_B, lambda m: _on_a_message(state, m), LISTEN_HOST_B),
        daemon=True,
    ).start()

    log.info('starting TLS req-reply (B -> setup) on %s:%d (loopback only)',
             LOCAL_LISTEN_HOST, LOCAL_LISTEN_PORT)
    threading.Thread(
        target=_link.serve_local,
        args=(LOCAL_LISTEN_PORT, lambda m: _on_setup_request(state, m)),
        kwargs={'host': LOCAL_LISTEN_HOST},
        daemon=True,
    ).start()

    log.info('=' * 60)
    log.info('  Module B ready. Awaiting cookie from Module A ...')
    log.info('=' * 60)

    _polling_loop(state)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        sys.exit(130)
