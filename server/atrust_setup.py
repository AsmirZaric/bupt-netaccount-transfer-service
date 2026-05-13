"""atrust_setup.py - drive Sangfor aTrust UI via pywinauto UIA backend.

Part of bupt-netaccount-transfer-service. Defaults are tuned for the
BUPT aTrust SSL-VPN at https://vpn.bupt.edu.cn (Chinese UI labels:
设置, 切换, 我已阅读并同意, 请输入账号, 请输入密码, 登录, 确定接入,
您已上线). The Chinese button / dialog text is part of aTrust itself
on Chinese-locale Windows installs — it ships that way, not because of
this script.

Phase 0 — pre-setup connectivity check (default mode only, NOT --test):
    Before touching aTrust at all, concurrently probe every URL in
    KEEPALIVE_URLS. If ANY one is reachable, the VPN is already up:
    skip all of Phase 1+2+3-login and jump straight to Phase 3 keepalive
    with grace=0. Only run the full setup flow if every site is down.
    Re-runs on every loop iteration so a self-recovered tunnel skips
    unnecessary aTrust restarts.

Phase 1 — access-address configuration (steps 1..4):
    1. Click '设置' (top nav)
    2. Click '切换' on the access-address row
    3. Type the access URL (from --url) char-by-char
    4. Click '确定接入'
    SKIPPED entirely if aTrust opened directly onto the login form
    (Edit '请输入账号' already visible at attach time) — typically
    because the access URL was set in a prior session and auto-resumed.

Phase 2 — login (steps 5..9):
    5. Wait for the login form to render (Edit '请输入账号') and concurrently
       fetch a fresh OTP from Module B over the loopback TLS req-reply
       channel (127.0.0.1:7001, _local.crt). The OTP is accepted only when
       its remaining lifetime >= --otp-min-remaining (default 5s).
    6. Toggle the '我已阅读并同意' CheckBox on (skip if already on).
    7. Type the captive-portal username (10-digit account ID).
    8. Type the OTP, then re-query B to confirm the typed code is still
       B's current code AND has >= --pre-login-otp-min seconds of life
       left (default 3s). If either check fails (TOTP rotated since type,
       or remaining slipped below threshold), fetch a fresh OTP and
       retype. Cap = MAX_OTP_TYPE_ATTEMPTS retries.
    9. Click '登录'; detect outcome within 15s:
          - main window closes / not visible       -> success
          - new aTrust top-level window containing
            '成功' / '已连接' / '已登录'             -> success (card)
          - new Text under main window containing
            '错误' / '次尝试' / '您还有'             -> failure (exit 1)
          - none of the above                      -> unknown (exit 2)

Phase 3 — connectivity keepalive (default mode only, NOT --test):
    After a successful login, sleep KEEPALIVE_GRACE_PERIOD seconds
    (default 10s) to let aTrust finish bringing up the tunnel + pushing
    routes, then enter a long-running watch loop:
      - once per second, probe ONE random URL from KEEPALIVE_URLS
      - if it fails, burst-probe ALL urls in parallel (3s timeout/url);
        success of any one means we're still online
      - if the burst also fully fails, treat the tunnel as down and
        re-run the whole setup flow (attach_or_launch kills + relaunches
        aTrust, matching the "就像最初启动那样" requirement)
    Ctrl+C exits the loop cleanly (including during the grace sleep)
    without triggering reconnect.

Modes:
    (default)  Run the full pipeline (steps 1..9), clicking 登录 at the end,
               then hold the connection alive via Phase 3 until Ctrl+C
               or a hard failure (login failure / unknown result).
    --test     Run steps 1..8 with the SAME real OTP fetched from B, then
               STOP just before clicking 登录. Skips Phase 3. Use this to
               verify the UI before consuming a real login attempt.
    --record   Passive UIA event recorder: log every aTrust-relevant click
               (with target attributes, parent path, sibling list) to
               _record.log. Ctrl+C to stop. No UI clicks are issued.

Strict invariants (avoid the "Windows Settings opens by accident" failure):
    - Every UIA wrapper that gets clicked must trace its top-level ancestor
      back to a window whose owning PID belongs to an aTrust*.exe process.
    - No fallback ever runs descendants() on the Desktop root.
    - No screenshots, no template matching, no fixed coordinates.
    - click_input() is only called on wrappers obtained from UIA searches.

Usage:
    python atrust_setup.py [--url URL] [--test | --record]
                           [--b-host H] [--b-port N] [--otp-min-remaining S]
                           [--verbose]

    --url URL             Access address for your aTrust VPN portal.
    --test                Walk steps 1..8 with real B-fetched OTP, but skip
                          the final 登录 click. Mutually exclusive with
                          --record.
    --record              Run the passive recorder; nothing else.
    --b-host H            Module B host for setup channel (default 127.0.0.1).
    --b-port N            Module B loopback port (default 7001).
    --otp-min-remaining S Reject OTP with remaining lifetime below S seconds
                          and wait for the next /otp cycle (default 5).
    --verbose             DEBUG-level logs (per-step candidate lists, UIA
                          wake/soak diagnostics, tree dumps).
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
import logging
import subprocess
import time
import traceback

try:
    from pywinauto import Desktop
    from pywinauto.timings import Timings
except ImportError as e:
    print(f'pip install pywinauto  ({e})', file=sys.stderr)
    sys.exit(2)

try:
    import psutil
except ImportError as e:
    print(f'pip install psutil  ({e})', file=sys.stderr)
    sys.exit(2)


EXE = r'C:\Program Files (x86)\Sangfor\aTrust\aTrustTray\aTrustTray.exe'
# aTrust portal URL. Default targets BUPT's official aTrust portal —
# this project is purpose-built for the BUPT aTrust SSL-VPN. Override
# via --url when adapting to a different institution.
DEFAULT_URL = 'https://vpn.bupt.edu.cn'

# B<->setup TLS req-reply channel (loopback only).
DEFAULT_B_HOST = '127.0.0.1'
DEFAULT_B_PORT = 7001
# OTP freshness: refuse to type an OTP whose remaining lifetime is below
# this. 5s gives ~3s buffer for typing/click before the server-side window
# closes (typing username+code+登录 takes ~2-3s).
DEFAULT_OTP_MIN_REMAINING = 5
# Total wait time at step 5 for both the login form to render AND for B
# to surface a fresh OTP. ~5 min covers the worst case (user takes their
# time to trigger OAuth on the WeChat side).
DEFAULT_OTP_WAIT_TIMEOUT = 300
# Window in which to detect login outcome after clicking 登录.
DEFAULT_LOGIN_RESULT_TIMEOUT = 15
# Minimum OTP remaining lifetime checked AFTER typing the OTP but BEFORE
# clicking 登录. If remaining dropped below this between the initial
# fetch and this recheck (because typing took longer than expected, or
# because we crossed a TOTP rotation), treat the typed code as stale,
# fetch a new OTP and re-type. The initial fetch threshold
# (--otp-min-remaining, default 5s) is intentionally higher so this
# recheck only triggers in edge cases.
DEFAULT_PRE_LOGIN_OTP_MIN = 3
# Hard cap on the type-OTP + recheck loop. Each retry costs up to one
# OTP period (~30s) waiting for B to surface the next sample. 5 retries
# is enough headroom that running out signals something structurally
# wrong (e.g. aTrust UI taking 5+ seconds per type pass).
MAX_OTP_TYPE_ATTEMPTS = 5
# How many times to retry the whole UI flow when a UIA tree-read error
# (an expected element didn't materialize) crashes a step. attach_or_launch
# kills + relaunches aTrust each retry, so retrying is safe — no
# failure-counter gets burned because we never reach the 登录 click.
MAX_UIA_RETRIES = 5


class UIATreeReadError(RuntimeError):
    """An expected UIA element wasn't found in the tree. Usually means
    Chromium's accessibility provider is dormant or aTrust is in a stale
    state. The setup loop catches this, kills aTrust, and retries with a
    fresh launch (up to MAX_UIA_RETRIES)."""
# Failure-signal keywords taken from the example error string
# '用户名或密码错误，您还有7次尝试的机会'. Intentionally narrow — we don't
# want to false-positive on benign UI text.
FAILURE_KEYWORDS = ('错误', '次尝试', '您还有')
# Success-card keywords. aTrust spawns a small Chrome_WidgetWin_1 popup
# (~522x256 at bottom-right) on successful login, owned by aTrustTray.exe,
# with a Text element whose UIA Name is '您已上线'. Captured via
# record_popup.py in the real flow; the recorder log shows:
#   NEW HWND  proc=aTrustTray.exe class='Chrome_WidgetWin_1' title='aTrust'
#     - Image:'check-circle-filled'
#     - Text :'您已上线'
#     - Text :'登录用户：... 登录地址：... 登录时间：...'
# Keep the other variants too — different aTrust versions may use them.
SUCCESS_CARD_KEYWORDS = (
    '您已上线',       # observed on aTrust 2.x (Chinese)
    '已连接', '连接成功',
    '已登录', '登录成功',
)

Timings.window_find_timeout = 20
Timings.window_find_retry = 0.4
Timings.after_click_wait = 0.5

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S',
)
log = logging.getLogger('atrust')


# ---------------------------------------------------------------------------
# UIA helpers
# ---------------------------------------------------------------------------

def _safe_text(ctrl) -> str:
    try:
        return (ctrl.window_text() or '').strip()
    except Exception:
        return ''


def _safe_ctype(ctrl) -> str:
    try:
        return ctrl.element_info.control_type or ''
    except Exception:
        return ''


def _safe_auto_id(ctrl) -> str:
    try:
        return ctrl.element_info.automation_id or ''
    except Exception:
        return ''


def _safe_class(ctrl) -> str:
    try:
        return ctrl.element_info.class_name or ''
    except Exception:
        return ''


def _safe_pid(ctrl) -> int:
    try:
        return ctrl.element_info.process_id or 0
    except Exception:
        return 0


def _safe_rect(ctrl):
    try:
        return ctrl.rectangle()
    except Exception:
        return None


def _is_visible(ctrl) -> bool:
    try:
        return bool(ctrl.is_visible())
    except Exception:
        return False


def _desc(ctrl) -> str:
    return (
        f'pid={_safe_pid(ctrl)} '
        f'text={_safe_text(ctrl)!r} '
        f'type={_safe_ctype(ctrl)} '
        f'auto_id={_safe_auto_id(ctrl)!r} '
        f'class={_safe_class(ctrl)!r} '
        f'rect={_safe_rect(ctrl)}'
    )


def _proc_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ''


def _all_descendants(window):
    try:
        return list(window.descendants())
    except Exception as e:
        log.error('descendants() failed: %s', e)
        return []


# ---------------------------------------------------------------------------
# aTrust process / window discovery
# ---------------------------------------------------------------------------

def _atrust_pids() -> set[int]:
    """Set of PIDs of any process whose image basename starts with 'aTrust'
    (case-insensitive). Captures aTrustTray, aTrustClient, aTrustConsole, etc."""
    out: set[int] = set()
    for p in psutil.process_iter(['pid', 'name']):
        name = (p.info.get('name') or '').lower()
        if name.startswith('atrust'):
            out.add(p.info['pid'])
    return out


def _ancestor_top_window(ctrl):
    """Walk up the UIA parent chain to the top-level window owning ctrl."""
    cur = ctrl
    last = ctrl
    for _ in range(40):
        try:
            parent = cur.parent()
        except Exception:
            return last
        if parent is None:
            return last
        last = cur
        cur = parent
    return cur


def _list_top_level_visible_windows():
    """Return list of (wrapper, pid, name, class, title, rect) for visible
    top-level UIA windows. Used by --inspect and by aTrust window picking."""
    out = []
    try:
        wins = Desktop(backend='uia').windows()
    except Exception as e:
        log.error('Desktop.windows() failed: %s', e)
        return out
    for w in wins:
        try:
            if not w.is_visible():
                continue
        except Exception:
            continue
        pid = _safe_pid(w)
        out.append((
            w, pid, _proc_name(pid),
            _safe_class(w), _safe_text(w), _safe_rect(w),
        ))
    return out


def _pick_atrust_main_window():
    """Return the largest visible top-level window whose owning process name
    starts with 'aTrust'. Returns None if none."""
    pids = _atrust_pids()
    if not pids:
        return None
    cands = []
    for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
        if pid not in pids:
            continue
        if rect is None:
            continue
        area = max(0, rect.width()) * max(0, rect.height())
        if area < 100 * 100:
            # Skip tiny windows like balloon tooltips or hidden helpers.
            continue
        cands.append((area, w, pid, pname, cls, title, rect))
    if not cands:
        return None
    cands.sort(reverse=True)  # largest first
    log.debug('aTrust window candidates (largest first):')
    for area, w, pid, pname, cls, title, rect in cands:
        log.debug('  pid=%d proc=%s class=%r title=%r rect=%s area=%d',
                  pid, pname, cls, title, rect, area)
    return cands[0][1]


def _exact_name_match(ctrl) -> bool:
    """Whether the control's accessible name is exactly 'aTrust' (with possible
    surrounding whitespace). Avoids substring false positives like a tooltip
    text containing the word 'aTrust' as part of a sentence."""
    return _safe_text(ctrl).strip() == 'aTrust'


def _find_in_tree(root, predicate):
    """Yield descendants of `root` matching `predicate`."""
    for ctrl in _all_descendants(root):
        try:
            if predicate(ctrl):
                yield ctrl
        except Exception:
            continue


def _click_aTrust_tray_icon():
    """Locate the aTrust icon in the (possibly hidden / overflowed) tray and
    single-click it. Win11 hides extra icons behind a flyout that opens via a
    'show hidden icons' button on the taskbar.

    Returns True if a click was issued. Every click target is verified to be
    a UIA element whose accessible name is EXACTLY 'aTrust'."""

    # ---- Path 1: icon directly in the visible part of the taskbar ----
    try:
        taskbar = Desktop(backend='uia').window(class_name='Shell_TrayWnd')
        taskbar.wait('visible', timeout=5)
        for ctrl in _find_in_tree(taskbar, _exact_name_match):
            log.debug('direct tray icon (exact "aTrust"): %s', _desc(ctrl))
            try:
                ctrl.click_input()
                return True
            except Exception as e:
                log.warning('direct tray click failed: %s', e)
    except Exception as e:
        log.warning('taskbar not reachable: %s', e)

    # ---- Path 2: open the Win11 overflow flyout, then click the icon ----
    # The "show hidden icons" button is on the taskbar and has class
    # SystemTray.NormalButton with a localized name. We don't depend on the
    # name's text; we depend on the AutomationId / class.
    log.debug('icon not in visible tray; trying overflow flyout')
    overflow_button = None
    try:
        taskbar = Desktop(backend='uia').window(class_name='Shell_TrayWnd')
        for ctrl in _all_descendants(taskbar):
            cls = _safe_class(ctrl)
            auto_id = _safe_auto_id(ctrl)
            if cls == 'SystemTray.NormalButton' and (
                'SystemTrayIconShowHidden' in auto_id or
                'Notification Chevron' in _safe_text(ctrl) or
                _safe_text(ctrl) in ('显示隐藏的图标', 'Show hidden icons')
            ):
                overflow_button = ctrl
                log.debug('overflow button: %s', _desc(ctrl))
                break
    except Exception as e:
        log.warning('couldn\'t scan taskbar for overflow button: %s', e)

    if overflow_button is None:
        # Last-ditch: try the legacy Win10 overflow window class directly.
        try:
            legacy = Desktop(backend='uia').window(class_name='NotifyIconOverflowWindow')
            legacy.wait('exists', timeout=1)
            for ctrl in _find_in_tree(legacy, _exact_name_match):
                log.debug('legacy overflow icon (exact "aTrust"): %s', _desc(ctrl))
                try:
                    ctrl.click_input()
                    return True
                except Exception:
                    pass
        except Exception:
            pass
        log.error('overflow button not found and no Win10 overflow window')
        return False

    try:
        overflow_button.click_input()
    except Exception as e:
        log.error('clicking overflow button failed: %s', e)
        return False

    # Wait for the overflow popup window. Win11 names vary across builds;
    # search by class fragments, then fall back to "any new visible window".
    overflow_popup = None
    deadline = time.monotonic() + 3.0
    seen_initial = {w.handle for w, *_ in _list_top_level_visible_windows()
                    if hasattr(w, 'handle')}
    while time.monotonic() < deadline:
        for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
            if not hasattr(w, 'handle'):
                continue
            if w.handle in seen_initial:
                continue
            # Most overflow popups are owned by explorer.exe and are small.
            if pname == 'explorer.exe' and rect is not None and rect.width() < 400:
                overflow_popup = w
                log.debug('overflow popup: pid=%d class=%r title=%r rect=%s',
                          pid, cls, title, rect)
                break
        if overflow_popup is not None:
            break
        time.sleep(0.2)

    if overflow_popup is None:
        log.error('overflow popup did not appear')
        return False

    # Click the aTrust icon inside the popup. EXACT name match for safety.
    for ctrl in _find_in_tree(overflow_popup, _exact_name_match):
        log.debug('overflow popup aTrust icon: %s', _desc(ctrl))
        try:
            ctrl.click_input()
            return True
        except Exception as e:
            log.warning('icon click failed: %s', e)
    log.error('no exact-"aTrust" icon found in overflow popup')
    return False


def _wait_for_atrust_window(timeout: float):
    """Poll for a visible aTrust-owned top-level window."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        w = _pick_atrust_main_window()
        if w is not None:
            return w
        time.sleep(0.15)
    return None


def _kill_all_atrust_tray() -> int:
    """Force-kill every aTrustTray.exe process. Used as a last-resort
    recovery when Chromium UIA is stuck in the existing instance."""
    import psutil as _ps
    killed = 0
    for p in _ps.process_iter(['pid', 'name']):
        try:
            if (p.info.get('name') or '').lower() == 'atrusttray.exe':
                p.kill()
                killed += 1
        except Exception:
            pass
    return killed


# Windows process-creation flags for fully detached spawn.
_DETACHED_PROCESS         = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW         = 0x08000000


def _launch_atrust_detached() -> bool:
    """Spawn aTrustTray.exe as a fully detached process.

    Why not `Application(backend='uia').start(EXE)`: pywinauto's start uses
    subprocess.Popen without stdio redirection, so aTrust's internal C++
    logger (sangfor::ssl::SSLSession etc.) inherits our stdout/stderr and
    spews lines like
        [...][ info][Tag null][sangfor::ssl::SSLSession::Start:203] ...
    straight into our terminal once aTrust starts its VPN session.

    Manual Popen with DEVNULL stdio + DETACHED_PROCESS detaches aTrust
    cleanly. Child processes aTrust spawns (e.g., its CEF renderer) inherit
    the redirected stdio, so the noise stays gone.

    Returns True on successful spawn. We don't track the PID; the caller
    locates the resulting window via _pick_atrust_main_window().
    """
    try:
        subprocess.Popen(
            [EXE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(_DETACHED_PROCESS |
                           _CREATE_NEW_PROCESS_GROUP |
                           _CREATE_NO_WINDOW),
            close_fds=True,
        )
        return True
    except Exception as e:
        log.error('failed to launch %s: %s', EXE, e)
        return False


def attach_or_launch():
    """Always kill + relaunch aTrust fresh, then return its main window.

    Long-running aTrustTray instances reliably end up with their CEF
    accessibility provider in a dormant state -- WM_GETOBJECT pokes and
    LegacyIAccessible property reads no longer wake the DOM tree, and
    find_inside() comes back empty. The previous "try existing first, retry
    on dormant" strategy still had to *detect* the dormant state, which cost
    a wasted 3s soak before triggering recovery.

    Unconditional restart removes that detection cost: the fresh CEF
    instance always has a healthy UIA tree, the soak always succeeds in
    ~0.1-0.5s, and total wall time is predictable across runs.
    """
    initial_pids = _atrust_pids()
    log.debug('aTrust* pids at start: %s', sorted(initial_pids))

    killed = _kill_all_atrust_tray()
    if killed:
        log.debug('killed %d stale aTrustTray instance(s) for fresh launch',
                  killed)
        time.sleep(0.3)

    if not _launch_atrust_detached():
        raise RuntimeError(f'failed to launch {EXE}')

    main_win = _wait_for_atrust_window(timeout=10)
    if main_win is not None:
        return main_win

    # Some Windows builds fail to surface the window on cold launch (rare).
    # Tray-icon click as last resort.
    log.debug('fresh launch did not surface a window; trying tray-icon click')
    if _click_aTrust_tray_icon():
        main_win = _wait_for_atrust_window(timeout=6)
        if main_win is not None:
            return main_win

    raise RuntimeError(
        'aTrust main UI window not located after fresh launch. '
        'Try opening aTrust manually once, or use --inspect to diagnose.'
    )


def ensure_healthy_ui(main_win):
    """Wake the UIA tree of the freshly-launched aTrust window.

    Since attach_or_launch always restarts aTrust, the Chromium UIA provider
    is fresh and should respond to the wake immediately. We still soak
    briefly because Chromium materializes the DOM asynchronously after
    receiving WM_GETOBJECT.
    """
    _bring_to_foreground(main_win)
    wn, hn = _activate_atrust_uia_trees()
    log.debug('UIA wake: poked %d HWND(s) across %d aTrust window(s)', hn, wn)
    if not _uia_soak(main_win, duration=3.0, min_named=5):
        raise RuntimeError(
            "Chromium UIA tree did not surface named elements after a fresh "
            "aTrust launch. aTrust may be in a broken state -- try "
            "reinstalling, or run with --verbose to inspect."
        )
    return main_win


# ---------------------------------------------------------------------------
# Strict in-window UIA search
# ---------------------------------------------------------------------------

def _in_window(ctrl, window) -> bool:
    """True iff ctrl's top-level ancestor is `window` (i.e., it actually lives
    inside the aTrust UI tree, not in some other system window we accidentally
    descended into)."""
    try:
        top = _ancestor_top_window(ctrl)
        return top.handle == window.handle if hasattr(top, 'handle') else top == window
    except Exception:
        # Best-effort PID match as a fallback.
        return _safe_pid(ctrl) == _safe_pid(window)


def find_inside(window, text: str = None, control_type: str = None,
                exact: bool = True, predicate=None):
    """Return all elements under `window` matching the filters.

    IMPORTANT: This uses IUIAutomation::FindAll with TreeScope_Subtree +
    TrueCondition **directly** on the raw element, bypassing pywinauto's
    `descendants()` (which uses ControlViewWalker). Chromium / CEF marks its
    DOM nodes as non-control-elements, so ControlViewWalker hides them --
    descendants() then returns only the few structural Panes with empty names.
    The raw FindAll path surfaces every DOM node Chromium has populated,
    including Text / Edit / Button / Hyperlink with their real names.
    """
    from pywinauto.uia_defines import IUIA
    from pywinauto.uia_element_info import UIAElementInfo
    from pywinauto.controls.uiawrapper import UIAWrapper

    out = []
    try:
        window_pid = _safe_pid(window)
        raw_root = window.element_info.element
        iuia = IUIA().iuia
        true_cond = iuia.CreateTrueCondition()
        TreeScope_Subtree = 7
        found = raw_root.FindAll(TreeScope_Subtree, true_cond)
    except Exception as e:
        log.debug('find_inside: FindAll setup failed: %s', e)
        return out
    if found is None:
        return out
    try:
        n = int(found.Length)
    except Exception:
        return out

    for i in range(n):
        try:
            elem = found.GetElement(i)
            info = UIAElementInfo(elem)
        except Exception:
            continue
        # Process-id filter (defensive; FindAll is window-scoped already).
        try:
            if (info.process_id or 0) != window_pid:
                continue
        except Exception:
            continue
        # Name / control-type filtering.
        if text is not None:
            try:
                t = (info.name or '').strip()
            except Exception:
                t = ''
            if exact:
                if t != text:
                    continue
            else:
                if text not in t:
                    continue
        if control_type is not None:
            try:
                ct = info.control_type or ''
            except Exception:
                ct = ''
            if ct != control_type:
                continue
        try:
            wrapper = UIAWrapper(info)
        except Exception:
            continue
        if predicate is not None:
            try:
                if not predicate(wrapper):
                    continue
            except Exception:
                continue
        out.append(wrapper)
    return out


def wait_for_element(window, *, control_type: str = None, text: str = None,
                     timeout: float = 6.0, must_be_actionable: bool = True):
    """Poll find_inside until at least one matching element exists.

    Hot-path is fast: the FIRST call to find_inside often returns immediately
    if the tree was populated by a prior step's wake / soak. We only re-wake
    Chromium (heavy: pixel sweep + LegacyIAccessible reads) if the cheap
    lookup keeps missing for 0.7s.

    Returns the list of matching wrappers (visible+enabled if
    must_be_actionable=True). Empty list on timeout.
    """
    deadline = time.monotonic() + timeout
    start = time.monotonic()
    last_repoke = -1.0  # force first re-poke after the grace window
    while time.monotonic() < deadline:
        cands = find_inside(window, control_type=control_type, text=text)
        if must_be_actionable:
            actionable = []
            for c in cands:
                try:
                    if c.is_visible() and c.is_enabled():
                        actionable.append(c)
                except Exception:
                    continue
            if actionable:
                return actionable
        else:
            if cands:
                return cands
        # Cheap polling first; only do the expensive UIA wake after 0.7s of
        # consistent misses (or every 1.5s thereafter).
        now = time.monotonic()
        if (now - start) > 0.7 and (now - last_repoke) > 1.5:
            _activate_atrust_uia_trees()
            last_repoke = now
        time.sleep(0.1)
    return []


def find_button_in_row(window, row_label: str, button_text: str):
    """Find a button whose UIA ancestor subtree also contains `row_label`."""
    labels = find_inside(window, text=row_label)
    if not labels:
        return None
    log.debug('  found %d 行锚点 (%r)', len(labels), row_label)
    for lab in labels:
        log.debug('    anchor: %s', _desc(lab))
        # Walk up to a reasonable parent and look for the button below it.
        parent = lab
        for level in range(6):
            try:
                parent = parent.parent()
            except Exception:
                break
            if parent is None:
                break
            if not _in_window(parent, window):
                # Walked outside the aTrust tree -- stop.
                break
            btns = []
            for ctrl in _all_descendants(parent):
                if _safe_pid(ctrl) != _safe_pid(window):
                    continue
                if _safe_text(ctrl) == button_text:
                    btns.append(ctrl)
            if btns:
                log.debug('    located %r at parent[%d]', button_text, level)
                # Prefer the first visible+enabled button
                for b in btns:
                    try:
                        if b.is_visible() and b.is_enabled():
                            return b
                    except Exception:
                        continue
                return btns[0]
    return None


def dump_tree(window, max_depth: int = 4) -> None:
    """Print a depth-limited view of the UIA subtree rooted at `window`.

    Uses print_control_identifiers if available (WindowSpecification), else
    falls back to a manual BFS walk -- needed because Desktop().windows()
    returns plain UIAWrapper instances which don't expose that method."""
    if hasattr(window, 'print_control_identifiers'):
        try:
            window.print_control_identifiers(depth=max_depth)
            return
        except Exception as e:
            log.error('print_control_identifiers failed: %s; falling back to manual walk', e)

    def _walk(ctrl, lvl: int):
        indent = '  ' * lvl
        try:
            print(f'{indent}{_desc(ctrl)}')
        except Exception as e:
            print(f'{indent}<err: {e}>')
            return
        if lvl >= max_depth:
            return
        try:
            children = ctrl.children()
        except Exception:
            children = []
        for c in children:
            _walk(c, lvl + 1)
    try:
        _walk(window, 0)
    except Exception as e:
        log.error('manual dump failed: %s', e)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def _pick_actionable(candidates, label: str):
    """Pick the first visible+enabled wrapper. Falls back to the first one if
    none report actionable (some Chromium-exposed elements have wonky
    is_enabled()). Returns (chosen, picked_from_visible_enabled?)."""
    for c in candidates:
        try:
            if c.is_visible() and c.is_enabled():
                return c, True
        except Exception:
            continue
    return (candidates[0], False) if candidates else (None, False)


def click_settings(main_win, label: str = '[1/4]') -> None:
    """Click the top-nav '设置' tab.

    aTrust is a CEF/Chromium app: this tab is exposed as a *Text* element
    (the inner Chinese label of the <div role=tab>), with UIA name '设置'.
    There's only one such Text in the entire window tree.
    """
    log.info('%s 点击「设置」', label)
    log.debug("locating 设置 (Text in top nav) ...")
    cands = wait_for_element(main_win, control_type='Text', text='设置',
                             timeout=8.0)
    log.debug('  %d Text candidate(s):', len(cands))
    for c in cands:
        log.debug('    %s', _desc(c))
    if not cands:
        raise UIATreeReadError("Text '设置' not found. Chromium UIA tree may "
                           "not be populated yet -- launch aTrust manually "
                           "once to seed, then re-run.")
    chosen, ok = _pick_actionable(cands, '设置')
    log.debug('  -> %s%s', _desc(chosen),
              '' if ok else '  (no actionable; using first)')
    chosen.click_input()


def click_switch_in_access_row(main_win, label: str = '[2/4]') -> None:
    """Click the '切换' button on the basic-settings page (the access-address
    row). Unlike the tabs, this one IS exposed as a real UIA Button by
    Chromium, so we don't need anchor-on-接入地址 row-walking."""
    log.info('%s 点击「切换」', label)
    log.debug("locating 切换 button on settings page ...")
    cands = wait_for_element(main_win, control_type='Button', text='切换',
                             timeout=8.0)
    if not cands:
        # Defensive fallback: some builds may expose 切换 as Text instead.
        log.debug('  no Button found; falling back to Text 切换')
        cands = wait_for_element(main_win, control_type='Text', text='切换',
                                 timeout=2.0)
    log.debug('  %d candidate(s):', len(cands))
    for c in cands:
        log.debug('    %s', _desc(c))
    if not cands:
        raise UIATreeReadError("'切换' not found on the settings page")
    chosen, ok = _pick_actionable(cands, '切换')
    log.debug('  -> %s%s', _desc(chosen),
              '' if ok else '  (no actionable; using first)')
    chosen.click_input()


def set_access_url(main_win, url: str, label: str = '[3/4]') -> None:
    """Find the URL Edit by its exact UIA name (placeholder text), clear it,
    type the new URL. The placeholder uses Chinese full-width parentheses."""
    URL_EDIT_NAME = '请输入地址（支持域名、IPv4、IPv6）'
    log.info('%s 输入 URL: %s', label, url)
    log.debug("locating URL Edit (name=%r) ...", URL_EDIT_NAME)
    cands = wait_for_element(main_win, control_type='Edit',
                             text=URL_EDIT_NAME, timeout=8.0)
    log.debug('  %d Edit candidate(s):', len(cands))
    for c in cands:
        log.debug('    %s', _desc(c))
    if not cands:
        raise UIATreeReadError(
            f"URL Edit not found (name={URL_EDIT_NAME!r}). "
            "Either '切换' didn't actually transition to the access-address "
            "panel, or aTrust's placeholder text changed in a newer build."
        )
    edit, _ = _pick_actionable(cands, 'URL Edit')
    log.debug('  -> %s', _desc(edit))

    try:
        edit.set_focus()
    except Exception:
        pass
    edit.click_input()
    time.sleep(0.1)
    # Clear any existing content. Try ValuePattern first (instant), fall back
    # to Ctrl+A / Delete keystrokes.
    try:
        edit.set_text('')
    except Exception as e:
        log.warning("set_text('') failed (%s); using ^a{DELETE}", e)
        edit.type_keys('^a{DELETE}', set_foreground=True)

    # Type character-by-character via SendInput keystrokes (set_text would
    # submit the whole string atomically and bypass any per-keystroke
    # validation / onInput handlers aTrust might have wired up).
    PER_CHAR_PAUSE = 0.015  # 15 ms between chars -- whole URL ~350ms
    log.debug('  typing %d chars at %dms/char', len(url),
              int(PER_CHAR_PAUSE * 1000))
    for ch in url:
        # `with_spaces=True` so a literal space wouldn't be eaten.
        # type_keys interprets `+ ^ % ( ) { } ~` as modifiers/specials;
        # none appear in a URL, but escape to be safe.
        if ch in '+^%(){}~':
            seq = '{' + ch + '}'
        else:
            seq = ch
        try:
            edit.type_keys(seq, pause=PER_CHAR_PAUSE, with_spaces=True,
                           set_foreground=False)
        except Exception as e:
            log.warning('type_keys(%r) failed: %s', ch, e)


# ---------------------------------------------------------------------------
# Phase 2 (login) helpers - placed before click_confirm_connect because
# Python resolves names at call time, the ordering is for readability.
# ---------------------------------------------------------------------------

# UIA pattern IDs needed for CheckBox state introspection.
_UIA_TogglePatternId        = 10009
# _UIA_LegacyIAccessiblePatternId is already defined later in the file
# (recorder section). We reference it by id 10018 below to avoid a
# forward-reference at import time.
_LEGACY_PATTERN_ID          = 10018

# IAccessible state bitmask flags (oleacc.h).
_STATE_SYSTEM_CHECKED       = 0x00000010
_STATE_SYSTEM_INDETERMINATE = 0x00000020
_STATE_SYSTEM_PRESSED       = 0x00000008
_STATE_SYSTEM_UNAVAILABLE   = 0x00000001


def _read_toggle_state(cb_wrapper) -> tuple[int, str]:
    """Return (state, source) where state is UIA ToggleState:
      0 = off, 1 = on, 2 = indeterminate, -1 = could not read.

    Chromium / CEF custom checkboxes don't always expose TogglePattern
    reliably — some builds expose only LegacyIAccessible with the
    STATE_SYSTEM_CHECKED bit in CurrentState. We try sources in order:

      1. UIA TogglePattern.CurrentToggleState (canonical, when present)
      2. LegacyIAccessible.CurrentState & 0x10 (MSAA bitmask)

    Returns (-1, '') if no source can answer. `source` names the method
    that succeeded so we can log it for diagnosability.
    """
    from pywinauto.uia_defines import IUIA
    try:
        raw = cb_wrapper.element_info.element
    except Exception as e:
        log.debug('  toggle state: element fetch failed: %s', e)
        return -1, ''

    # --- 1. UIA TogglePattern --------------------------------------------
    try:
        pat_obj = raw.GetCurrentPattern(_UIA_TogglePatternId)
        if pat_obj is not None:
            iface = IUIA().UIA_dll.IUIAutomationTogglePattern
            pat = pat_obj.QueryInterface(iface)
            s = int(pat.CurrentToggleState)
            return s, 'TogglePattern'
    except Exception as e:
        log.debug('  TogglePattern read failed: %s', e)

    # --- 2. LegacyIAccessible CurrentState bitmask ------------------------
    try:
        pat_obj = raw.GetCurrentPattern(_LEGACY_PATTERN_ID)
        if pat_obj is not None:
            iface = IUIA().UIA_dll.IUIAutomationLegacyIAccessiblePattern
            pat = pat_obj.QueryInterface(iface)
            try:
                cs = int(pat.CurrentState)
            except Exception:
                cs = 0
            if cs & _STATE_SYSTEM_INDETERMINATE:
                return 2, f'LegacyIAccessible(state=0x{cs:x})'
            if cs & _STATE_SYSTEM_CHECKED:
                return 1, f'LegacyIAccessible(state=0x{cs:x})'
            return 0, f'LegacyIAccessible(state=0x{cs:x})'
    except Exception as e:
        log.debug('  LegacyIAccessible read failed: %s', e)

    return -1, ''


def _wait_keyboard_focus(edit, timeout: float = 2.0) -> bool:
    """Poll UIA CurrentHasKeyboardFocus until the Edit actually owns the
    keyboard, or timeout. Critical before sending any keyboard input that
    relies on focus (^A, Backspace, even bare typing in some cases).

    The reason this is needed: Chromium's blur+focus handling for DOM
    elements is asynchronous. After click_input() the OS-level focus is
    transferred but Chromium's internal focused element pointer may take
    tens to hundreds of milliseconds to settle. SendInput'd keystrokes in
    that window route to whatever Chromium currently considers focused —
    typically the parent Document — which causes Ctrl+A to select the
    entire page instead of the Edit's contents.
    """
    deadline = time.monotonic() + timeout
    raw = None
    try:
        raw = edit.element_info.element
    except Exception:
        return False
    while time.monotonic() < deadline:
        try:
            if bool(raw.CurrentHasKeyboardFocus):
                return True
        except Exception:
            pass
        time.sleep(0.04)
    return False


# Inter-character pause for type_keys (applied between each keystroke
# internally by pywinauto). Chromium-CEF can drop chars if they arrive
# faster than the DOM input pipeline can absorb them.
#   _TYPE_PAUSE_FAST — username (10 digits at page-load, focus is stable).
#   _TYPE_PAUSE_OTP  — OTP password. Slower to give the username->password
#                       DOM blur+focus transition more headroom.
_TYPE_PAUSE_FAST = 0.030
_TYPE_PAUSE_OTP  = 0.050
# Settle window after focus is acquired on an Edit, before typing starts.
# UIA HasKeyboardFocus goes True before Chromium's document.activeElement
# actually points at the Edit — typing during that gap routes chars to
# the previously-focused element. 350ms covers the worst case observed
# for the username -> password transition.
_FOCUS_SETTLE = 0.35


def _escape_sendinput(text: str) -> str:
    """Escape pywinauto's type_keys special chars."""
    out = []
    for ch in text:
        if ch in '+^%(){}~':
            out.append('{' + ch + '}')
        else:
            out.append(ch)
    return ''.join(out)


def _verify_value(edit, expected: str, allow_masked: bool):
    """Read the Edit's ValuePattern after a brief settle. Returns
    (matched: bool, actual: str)."""
    time.sleep(0.08)
    try:
        actual = _value_pattern(edit.element_info.element)
    except Exception:
        actual = ''
    if actual == expected:
        return True, actual
    if allow_masked and len(actual) == len(expected):
        return True, actual
    return False, actual


def _type_per_char(edit, text: str, label: str = '',
                   allow_masked_verify: bool = False,
                   per_char_pause: float = _TYPE_PAUSE_FAST) -> None:
    """Focus `edit`, then clear+type `text` in ONE batched type_keys call
    ('^a{DELETE}' + text). Verify via ValuePattern read-back; one
    automatic retry on verify failure.

    Why the batched ^a{DELETE}+text (over set_text('') then a separate
    type_keys): set_text() invokes ValuePattern.SetValue, which on
    aTrust's Chromium build resets DOM activeElement — the first few
    subsequent keystrokes then leak to a stale focus target. That was
    the source of the "only 4 of 6 OTP chars land" failure under the
    username→OTP transition. Sending ^a{DELETE} and the digits in ONE
    type_keys call keeps focus held throughout the SendInput stream;
    a 5×iteration stress test on the live form confirmed first-attempt
    success across all iters before this was promoted into production.

    Focus strategy: UIA `set_focus` FIRST (a pure DOM-focus request
    Chromium honors without the mouse-event side effects of click_input),
    with click_input as fallback only if set_focus raises. Then wait
    HasKeyboardFocus (≤2s), then 350ms settle so DOM activeElement
    catches up to UIA HasKeyboardFocus before the keystrokes flow.

    Retry covers residual race risk: zero cost on the fast path, ~600ms
    extra on failure. `allow_masked_verify` accepts equal-LENGTH masked
    read-backs (●●●) for password Edits.
    """
    escaped = _escape_sendinput(text)
    payload = '^a{DELETE}' + escaped

    def _attempt() -> tuple[bool, str]:
        # Focus: UIA set_focus first, click_input fallback only on exception.
        try:
            edit.set_focus()
        except Exception as e:
            log.debug('  set_focus on %s failed (%s); falling back to click_input',
                      label or 'edit', e)
            try:
                edit.click_input()
            except Exception as e2:
                log.warning('  click_input on %s also failed: %s',
                            label or 'edit', e2)
        _wait_keyboard_focus(edit, timeout=2.0)
        time.sleep(_FOCUS_SETTLE)
        # Clear+type in ONE SendInput stream (no intermediate set_text).
        try:
            edit.type_keys(payload, pause=per_char_pause,
                           with_spaces=True, set_foreground=False)
        except Exception as e:
            log.warning('  type_keys(%r) in %s failed: %s', text, label, e)
        return _verify_value(edit, text, allow_masked_verify)

    # --- Attempt 1 --------------------------------------------------------
    ok, actual = _attempt()
    if ok:
        log.info('  %s 校验通过 (%d chars%s, pause=%dms)',
                 label or 'edit', len(text),
                 ', masked' if (allow_masked_verify and actual != text) else '',
                 int(per_char_pause * 1000))
        return

    # --- Attempt 2 (retry) ------------------------------------------------
    log.warning('  %s 首次校验失败 (got %d chars: %r, want %d: %r); '
                '重试一次 (re-focus + re-clear + re-type)',
                label or 'edit', len(actual), actual, len(text), text)
    ok2, actual2 = _attempt()
    if ok2:
        log.info('  %s 校验通过 after retry (%d chars%s)',
                 label or 'edit', len(text),
                 ', masked' if (allow_masked_verify and actual2 != text) else '')
        return

    raise RuntimeError(
        f'{label or "edit"} 输入校验失败 (两次尝试均失败): '
        f'期望 {len(text)} 字符, 实际 {len(actual2)} 字符 '
        f'(got {actual2!r}, want {text!r}). '
        '已中止以避免错误凭据消耗 aTrust 登录尝试次数。'
    )


def wait_for_login_form(main_win, timeout: float = 30.0):
    """Block until Edit '请输入账号' is visible AND enabled inside main_win.

    Returns the (possibly re-acquired) main_win. After 确定接入 the same
    Chromium Pane stays alive but its Document content swaps to the login
    form; we just need to wait for the new Edit to materialize. If the
    window handle was somehow invalidated (rare), re-acquire by picking the
    largest aTrust*-owned top-level window.

    INFO log every 5s while waiting describes what's currently visible so
    the user can tell whether aTrust is mid-transition vs. stuck on a
    connection-error page vs. tree dormant.
    """
    deadline = time.monotonic() + timeout
    win = main_win
    last_snapshot = None  # tuple of (edit_names_tuple, text_names_tuple)
    while time.monotonic() < deadline:
        try:
            still_alive = bool(_user32.IsWindow(int(win.handle))) and \
                          win.is_visible()
        except Exception:
            still_alive = False
        if not still_alive:
            new_win = _pick_atrust_main_window()
            if new_win is not None:
                log.info('  主窗口换 handle, re-acquired: %r',
                         getattr(new_win, 'handle', None))
                win = new_win
        cands = find_inside(win, control_type='Edit', text='请输入账号')
        actionable = []
        for c in cands:
            try:
                if c.is_visible() and c.is_enabled():
                    actionable.append(c)
            except Exception:
                continue
        if actionable:
            return win

        # Dump current Edit + Text names ONLY when the page actually
        # changes (different set of named children). Polling 3x/sec with
        # an unchanged page would otherwise spam the same diagnostic.
        edits = find_inside(win, control_type='Edit')
        edit_names = tuple(sorted({
            (e.element_info.name or '').strip() for e in edits
        } - {''}))
        texts = find_inside(win, control_type='Text')
        text_names = tuple(sorted({
            (t.element_info.name or '').strip() for t in texts
        } - {''})[:12])
        snapshot = (edit_names, text_names)
        if snapshot != last_snapshot:
            log.info("  仍在等登录页 (Edit '请输入账号')...")
            log.info('    当前 Edit: %s', list(edit_names) or '(none)')
            log.info('    当前 Text (前 12): %s', list(text_names) or '(none)')
            last_snapshot = snapshot

        _activate_atrust_uia_trees()
        time.sleep(0.3)
    raise UIATreeReadError(
        f"login form (Edit '请输入账号') did not render in {timeout:.0f}s "
        "after clicking 确定接入"
    )


def _is_at_login_form(main_win, settle: float = 1.5) -> bool:
    """Passive check: is the login form's '请输入账号' Edit visible and
    enabled inside main_win right now?

    Used immediately after attach_or_launch + ensure_healthy_ui to detect
    the case where aTrust opens DIRECTLY to the login page -- typically
    because the access URL was already configured by a prior session and
    aTrust auto-resumed. In that case Phase 1 (steps 1-4: settings →
    switch → URL → 接入) is unnecessary and we jump straight to Phase 2.

    Cheap polling (~6 cycles over `settle` seconds) using find_inside on
    the already-warm tree -- intentionally does NOT re-poke UIA (that's
    what `_activate_atrust_uia_trees` is for; ensure_healthy_ui has
    already done it). Returns False on settle expiry, in which case the
    caller falls through to Phase 1 as the normal path.
    """
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        cands = find_inside(main_win, control_type='Edit', text='请输入账号')
        for c in cands:
            try:
                if c.is_visible() and c.is_enabled():
                    return True
            except Exception:
                continue
        time.sleep(0.25)
    return False


def verify_b_reachable(b_host: str, b_port: int,
                       timeout: float = 2.0) -> tuple[bool, str]:
    """Pre-flight ping of B's loopback setup channel before kicking off
    aTrust. Returns (reachable, status_message).

    "Reachable" only means TLS handshake succeeded and B answered the
    `ping` -> `pong` round-trip. It does NOT mean B has an OTP ready —
    that's checked downstream in fetch_fresh_otp where has_otp=False is a
    valid waiting state.
    """
    import _link
    try:
        reply = _link.request(b_host, b_port, {'type': 'ping'},
                              timeout=timeout)
    except Exception as e:
        # ConnectionRefusedError, socket.timeout, ssl.SSLError, etc.
        return False, f'{type(e).__name__}: {e}'
    if isinstance(reply, dict) and reply.get('type') == 'pong':
        return True, 'pong'
    return False, f'unexpected reply: {reply!r}'


def fetch_fresh_otp(b_host: str, b_port: int,
                    min_remaining: int = DEFAULT_OTP_MIN_REMAINING,
                    timeout: float = DEFAULT_OTP_WAIT_TIMEOUT):
    """Poll B over loopback TLS until it returns a non-stale OTP.

    Each poll = one short-lived TLS request (~10-30ms on loopback). If B
    responds with has_otp=False (A hasn't delivered the cookie yet) or with
    a stale OTP, we sleep 0.5s and try again. The B side updates its cached
    OTP after every successful /otp poll, so worst-case wait until a fresh
    sample is one OTP period (~30s).

    Status messages are logged at INFO every ~5s so the user can tell what
    we're waiting on (B unreachable / cookie pending / OTP stale).

    Returns (otp_dict, remaining_seconds). Raises TimeoutError after
    `timeout` seconds of trying.
    """
    import _link
    log.info('  查询 B 取 OTP (%s:%d)...', b_host, b_port)
    deadline = time.monotonic() + timeout
    last_status = ''   # 'unreachable' / 'no_otp:<reason>' / 'stale'

    def maybe_log(status: str, msg: str) -> None:
        nonlocal last_status
        # Log ONLY on status change. Repeating the same "waiting" line every
        # few seconds is just noise — the operator already knows we're
        # blocked on whatever the previous line said.
        if status != last_status:
            log.info('  %s', msg)
            last_status = status

    while time.monotonic() < deadline:
        try:
            reply = _link.request(b_host, b_port,
                                  {'type': 'get_otp'},
                                  timeout=3)
        except Exception as e:
            maybe_log('unreachable',
                      f'B 不可达 ({type(e).__name__}: {e}); 重试中... '
                      '(请确认 B 正在运行: bash run_b.sh)')
            time.sleep(0.5)
            continue
        if not reply or reply.get('type') != 'otp_state':
            maybe_log('bad_reply',
                      f'B 回复格式异常: {reply!r}; 重试中...')
            time.sleep(0.5)
            continue
        if not reply.get('has_otp'):
            reason = reply.get('reason', 'unknown')
            maybe_log(f'no_otp:{reason}',
                      f'B 尚无 OTP 缓存 (reason={reason}); '
                      '等 A 投递 cookie 后 B 会自动开始轮询 /otp')
            time.sleep(0.5)
            continue
        try:
            remaining = float(reply['expires_in']) - \
                        (time.time() - float(reply['written_at']))
        except Exception as e:
            maybe_log('malformed',
                      f'B 回复 OTP 字段缺失: {reply}; 重试中...')
            time.sleep(0.5)
            continue
        if remaining < min_remaining:
            maybe_log('stale',
                      f'OTP 剩余 {remaining:.1f}s < {min_remaining}s '
                      '阈值, 等 B 下一轮...')
            time.sleep(0.5)
            continue
        return reply, remaining
    raise TimeoutError(
        f'no fresh OTP from B at {b_host}:{b_port} within {timeout:.0f}s'
    )


def check_typed_otp_still_fresh(b_host: str, b_port: int,
                                typed_otp_code: str,
                                min_remaining: int = DEFAULT_PRE_LOGIN_OTP_MIN
                                ) -> tuple[bool, str]:
    """Single-shot B query to confirm the OTP we just typed into the
    password Edit is STILL the OTP B considers current, AND has at least
    `min_remaining` seconds of life left. Run immediately after
    type_password, just before clicking 登录.

    Returns (still_fresh, info_string). `info_string` is human-readable
    diagnostic (the staleness reason on False, the remaining seconds on
    True) and is logged at the call site.

    A "stale" outcome (still_fresh=False) can happen for two reasons:
      - the typed code no longer matches B's current code (TOTP rotated
        between fetch and type)
      - the typed code matches but remaining lifetime is too short for
        the upcoming 登录 click + server-side validation to land in time
    Either case requires fetching a new OTP and re-typing.
    """
    import _link
    try:
        reply = _link.request(b_host, b_port, {'type': 'get_otp'}, timeout=3)
    except Exception as e:
        return False, f'B unreachable ({type(e).__name__}: {e})'
    if not isinstance(reply, dict) or reply.get('type') != 'otp_state':
        return False, f'malformed reply: {reply!r}'
    if not reply.get('has_otp'):
        return False, f"B has no OTP cached (reason={reply.get('reason', 'unknown')})"
    current = reply.get('code', '') or ''
    if current != typed_otp_code:
        # Never log full OTP codes; just enough digits to disambiguate.
        cur_short = (current[:2] + '…' + current[-1:]) if len(current) >= 4 else current
        typ_short = (typed_otp_code[:2] + '…' + typed_otp_code[-1:]) \
                    if len(typed_otp_code) >= 4 else typed_otp_code
        return False, f'OTP rotated since type (current={cur_short}, typed={typ_short})'
    try:
        remaining = float(reply['expires_in']) - \
                    (time.time() - float(reply['written_at']))
    except Exception as e:
        return False, f'reply timing malformed: {e}'
    if remaining < min_remaining:
        return False, f'剩余 {remaining:.1f}s < {min_remaining}s 阈值'
    return True, f'remaining={remaining:.1f}s'


def _snapshot_named_elements(window) -> set[tuple]:
    """Set of (control_type_id, name) for all named UIA descendants of
    `window`. Used to compute new-Texts diff after click 登录.

    Direct-COM implementation: reads CurrentName + CurrentControlType
    straight from raw UIA elements, skipping the pywinauto
    UIAElementInfo + UIAWrapper allocations that `find_inside` does. For
    a typical aTrust login form (~40-50 elements) this drops the cost
    from ~400ms to ~50ms — important because check_login_result polls
    this every 0.5s after clicking 登录.

    The returned tuples use the *integer* control-type id (not the
    human-readable string); diff consumers (check_login_result) compare
    by name only, so the int form is fine."""
    out: set[tuple] = set()
    try:
        from pywinauto.uia_defines import IUIA
        raw_root = window.element_info.element
        iuia = IUIA().iuia
        true_cond = iuia.CreateTrueCondition()
        found = raw_root.FindAll(7, true_cond)  # TreeScope_Subtree
        n = int(found.Length)
    except Exception as e:
        log.debug('  snapshot failed: %s', e)
        return out

    for i in range(n):
        try:
            elem = found.GetElement(i)
            name = (elem.CurrentName or '').strip()
            if not name:
                continue
            ct = elem.CurrentControlType  # int
            out.add((ct, name))
        except Exception:
            continue
    return out


def _atrust_toplevel_handles() -> set[int]:
    """HWNDs of visible top-level windows owned by aTrust* processes.

    Path: Win32 EnumWindows → unique owner PIDs → psutil.Process(pid).name()
    for that small set only. ~20-50ms on a typical desktop.

    The old `_atrust_pids()` shortcut scanned EVERY process on the system
    via `psutil.process_iter()` (200+ procs → ~1.2s); this version scans
    only the PIDs that actually own visible top-level windows (typically
    15-30), which is what we care about anyway."""
    hwnds = _enum_visible_toplevel_hwnds()
    if not hwnds:
        return set()
    pid_to_hwnds: dict[int, list[int]] = {}
    for h in hwnds:
        pid_to_hwnds.setdefault(_hwnd_owner_pid(h), []).append(h)
    out: set[int] = set()
    for pid, hs in pid_to_hwnds.items():
        try:
            if psutil.Process(pid).name().lower().startswith('atrust'):
                out.update(hs)
        except Exception:
            continue
    return out


def _scan_new_window_for_card(handles: set[int]) -> str:
    """Scan a set of aTrust top-level window handles for success-card text.

    Returns the matching text or '' if none found. We poke each window's
    UIA tree first because newly-spawned Chromium popups start with a
    dormant accessibility tree."""
    for h in handles:
        try:
            _poke_uia_activate(h)
        except Exception:
            pass
        # Locate the wrapper for this handle.
        target_w = None
        for w, pid, *_ in _list_top_level_visible_windows():
            if hasattr(w, 'handle') and int(w.handle) == h:
                target_w = w
                break
        if target_w is None:
            continue
        try:
            items = find_inside(target_w)
        except Exception:
            items = []
        for c in items:
            try:
                n = (c.element_info.name or '').strip()
            except Exception:
                continue
            if not n:
                continue
            for kw in SUCCESS_CARD_KEYWORDS:
                if kw in n:
                    return n
    return ''


def _find_terms_checkbox(main_win, timeout: float = 8.0):
    """Locate the '我已阅读并同意' CheckBox with progressive fallbacks.

    Tries strict name match first, then partial-name match, then any
    CheckBox under main_win (the login form has exactly one — see
    _record.log: CheckBox:我已阅读并同意 alongside Hyperlink:《用户协议》).
    """
    cands = wait_for_element(main_win, control_type='CheckBox',
                             text='我已阅读并同意', timeout=timeout)
    if cands:
        return cands, 'exact-name'
    # Partial: contains '阅读并同意' (in case there's trailing/leading text)
    cands = find_inside(main_win, control_type='CheckBox',
                        text='阅读并同意', exact=False)
    actionable = [c for c in cands if _safe_visible_enabled(c)]
    if actionable:
        return actionable, 'partial-name'
    # Last resort: any visible+enabled CheckBox in main window.
    all_cbs = find_inside(main_win, control_type='CheckBox')
    actionable = [c for c in all_cbs if _safe_visible_enabled(c)]
    if actionable:
        return actionable, 'any-checkbox'
    return [], ''


def _safe_visible_enabled(c) -> bool:
    try:
        return c.is_visible() and c.is_enabled()
    except Exception:
        return False


def check_terms_checkbox(main_win, label: str = '[6/9]') -> None:
    """Ensure '我已阅读并同意' is checked. Verify state after click — if
    the click somehow flipped it the wrong way (e.g., our initial read
    misclassified state-unknown as state-off), click again to recover.

    This is critical for login: an unchecked terms box silently fails
    aTrust auth without producing an obvious error popup, which would
    consume a precious login attempt for no diagnostic value.
    """
    log.info('%s 勾选条款', label)
    cands, source = _find_terms_checkbox(main_win, timeout=8.0)
    if not cands:
        raise UIATreeReadError("CheckBox '我已阅读并同意' not found (also failed "
                           "partial '阅读并同意' and any-CheckBox fallback)")
    cb, _ = _pick_actionable(cands, '条款 CheckBox')
    log.debug('  found via %s: %s', source, _desc(cb))

    initial, src = _read_toggle_state(cb)
    log.debug('  initial state: %s (via %s)', initial,
              src or '<no source — pattern not exposed>')

    if initial == 1:
        log.info('  -> 已勾选, 跳过点击')
        return

    # Click once and verify.
    cb.click_input()
    time.sleep(0.3)
    after_click, src2 = _read_toggle_state(cb)
    log.debug('  after first click: %s (via %s)', after_click,
              src2 or '<no source>')

    if after_click == 1:
        log.info('  -> 已勾选')
        return

    if after_click == 0:
        # We just flipped it OFF — initial must have been ON (our pre-read
        # was wrong). Click again to put it back ON.
        log.warning('  first click toggled OFF (initial state was on but '
                    'misread as off/unknown). Clicking again to recover.')
        cb.click_input()
        time.sleep(0.3)
        verify, src3 = _read_toggle_state(cb)
        log.debug('  after recovery click: %s (via %s)', verify,
                  src3 or '<no source>')
        if verify == 1:
            log.info('  -> 已勾选 (after recovery)')
            return
        raise UIATreeReadError(
            f'条款 CheckBox state is {verify} after 2 clicks; can\'t '
            'guarantee it\'s checked — abort to avoid wasting a login '
            'attempt with unchecked terms.'
        )

    # after_click is -1 (still can't read) or 2 (indeterminate).
    # Without a reliable state read, we cannot proceed safely — clicking
    # again would either fix nothing or flip it the wrong way. Bail out
    # with a clear error pointing the operator at --diag-checkbox.
    raise UIATreeReadError(
        f'条款 CheckBox state unreadable after click (got {after_click}, '
        f'source={src2!r}). Run: python atrust_setup.py --diag-checkbox '
        '(after aTrust is at the login page) and share the output.'
    )


def type_username(main_win, username: str, label: str = '[7/9]') -> None:
    log.info('%s 输入用户名: %s', label, username)
    cands = wait_for_element(main_win, control_type='Edit',
                             text='请输入账号', timeout=8.0)
    if not cands:
        raise UIATreeReadError("Edit '请输入账号' not found")
    edit, _ = _pick_actionable(cands, '用户名 Edit')
    # Username is plaintext — exact match.
    _type_per_char(edit, username, label='username', allow_masked_verify=False)
    # Let aTrust's username on-blur JS validator commit BEFORE we go to
    # the password field. Without this delay, clicking password Edit
    # triggers username's blur handler, which holds DOM focus on username
    # while it validates — and the first few OTP chars then leak to it.
    time.sleep(0.30)


def type_password(main_win, otp_code: str, label: str = '[8/9]') -> None:
    # Never log the OTP code itself - just the length, for diagnostics.
    log.info('%s 输入 OTP (%d 位, %dms/char)', label, len(otp_code),
             int(_TYPE_PAUSE_OTP * 1000))
    cands = wait_for_element(main_win, control_type='Edit',
                             text='请输入密码', timeout=8.0)
    if not cands:
        raise UIATreeReadError("Edit '请输入密码' not found")
    edit, _ = _pick_actionable(cands, '密码 Edit')
    # Password Edit's ValuePattern may return masked bullets or empty —
    # fall back to length match. Use the slower OTP cadence (100ms/char)
    # to give Chromium time to absorb each key during the username->
    # password focus transition.
    _type_per_char(edit, otp_code, label='OTP',
                   allow_masked_verify=True,
                   per_char_pause=_TYPE_PAUSE_OTP)


def click_login(main_win, label: str = '[9/9]'):
    """Click '登录' Button and return the wrapper that was clicked.

    The login button is exposed as a real UIA Button by Chromium (per the
    raw FindAll dump on the login page state). Fall back to Text if a
    future aTrust build changes the markup."""
    log.info('%s 点击「登录」', label)
    cands = wait_for_element(main_win, control_type='Button',
                             text='登录', timeout=8.0)
    if not cands:
        log.debug('  no Button found; trying Text')
        cands = wait_for_element(main_win, control_type='Text',
                                 text='登录', timeout=2.0)
    if not cands:
        raise UIATreeReadError("Button/Text '登录' not found")
    btn, _ = _pick_actionable(cands, '登录')
    log.debug('  -> %s', _desc(btn))
    btn.click_input()
    return btn


def check_login_result(main_win,
                       baseline_texts: set[tuple[str, str]],
                       baseline_handles: set[int],
                       timeout: float = DEFAULT_LOGIN_RESULT_TIMEOUT):
    """Poll for the outcome of the 登录 click for up to `timeout` seconds.

    Returns one of:
        ('success_window_gone', None)
        ('success_in_place',    '<new Text inside main_win>')
        ('success_card',        '<text from a new aTrust top-level window>')
        ('failure',             '<failure Text inside main_win>')
        ('unknown',             None)
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # 1. Main window closed / not visible: definitive success.
        try:
            handle = int(main_win.handle)
            alive = bool(_user32.IsWindow(handle)) and main_win.is_visible()
        except Exception:
            alive = False
        if not alive:
            return ('success_window_gone', None)

        # 2. Card popup with success text. Newly-appeared aTrust top-levels.
        new_handles = _atrust_toplevel_handles() - baseline_handles
        # The main_win itself shouldn't be considered "new"; exclude it.
        try:
            new_handles.discard(int(main_win.handle))
        except Exception:
            pass
        if new_handles:
            card_text = _scan_new_window_for_card(new_handles)
            if card_text:
                return ('success_card', card_text)

        # 3. In-place success: new Text under main_win contains success kw.
        # 4. Failure: new Text under main_win contains failure kw.
        try:
            current_texts = _snapshot_named_elements(main_win)
        except Exception:
            current_texts = set()
        new_texts = current_texts - baseline_texts
        for ct, name in new_texts:
            if not name:
                continue
            # Check failure first (the error message is the explicit signal
            # we have a concrete sample for).
            for kw in FAILURE_KEYWORDS:
                if kw in name:
                    return ('failure', name)
            for kw in SUCCESS_CARD_KEYWORDS:
                if kw in name:
                    return ('success_in_place', name)

        time.sleep(0.5)
    return ('unknown', None)


# ---------------------------------------------------------------------------
# Production-mode connectivity keepalive
#
# After successful login, periodically probe BUPT intranet URLs to confirm
# the VPN tunnel is still live. On disconnection, the caller re-runs the
# whole setup flow (attach_or_launch kills + relaunches aTrust), which is
# what the user wants for "如最初启动那样" behavior.
# ---------------------------------------------------------------------------

# Intranet sites only reachable when the VPN tunnel is up. Used as a
# liveness probe. Defaults target BUPT campus systems — diverse
# subdomains and application stacks so a single-system outage doesn't
# false-positive as "VPN down". Override via --keepalive-url
# (repeatable) when adapting to a different institution.
KEEPALIVE_URLS: tuple = (
    'http://cwxt.bupt.edu.cn/Newindex.aspx',
    'http://tv.byr.cn/show',
    'http://my.bupt.edu.cn/xs_index.jsp?urltype=tree.TreeTempUrl&wbtreeid=1541',
    'http://software.bupt.edu.cn/',
    'http://zzgz.bupt.edu.cn/cas',
)
KEEPALIVE_PROBE_INTERVAL = 1.0      # 1Hz baseline probe
KEEPALIVE_PROBE_TIMEOUT  = 3        # seconds per HTTP probe
# Quiet period AFTER login succeeds, BEFORE the first probe. aTrust takes
# a couple of seconds post-登录 to actually establish the tunnel + push
# routes; probing immediately races that setup and would false-positive
# as "disconnected". 10s is conservative enough to cover slow links +
# tunnel renegotiation without blocking the user too long on Ctrl+C.
KEEPALIVE_GRACE_PERIOD = 10

# Some intranet sites use self-signed or hostname-mismatched certs; we
# deliberately disable cert verification and silence the warning so the
# keepalive log doesn't get polluted on every probe.
try:
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def _probe_url(url: str, timeout: float = KEEPALIVE_PROBE_TIMEOUT) -> bool:
    """Single-shot reachability probe. Returns True iff the target host
    returned ANY HTTP response within `timeout`. Connection refused, DNS
    failure, TLS handshake timeout, and read timeout all return False.

    Doesn't follow redirects (some auth-required sites loop on 302→login).
    Doesn't verify certs (mixed campus PKI). All we need is "did the
    TCP+TLS handshake complete and the server speak HTTP" -- which only
    works when the VPN tunnel is routing traffic to BUPT's intranet.
    """
    import requests
    try:
        requests.get(url, timeout=timeout,
                     allow_redirects=False, verify=False)
        return True
    except Exception:
        return False


def _burst_probe_all() -> tuple[bool, str]:
    """Concurrent probe of ALL KEEPALIVE_URLS, each with KEEPALIVE_PROBE_TIMEOUT
    per request. Returns (any_alive, first_alive_url) -- short-circuits
    as soon as one returns True. Returns (False, '') only if every site
    failed within its timeout.

    Used by:
      - main()'s pre-setup probe: if the VPN tunnel is already up,
        skip aTrust UI automation entirely and go straight to keepalive
      - keepalive_loop's burst-recovery branch: confirm an isolated
        probe miss isn't actually the whole tunnel going dark
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=len(KEEPALIVE_URLS)) as ex:
        futures = {ex.submit(_probe_url, u): u for u in KEEPALIVE_URLS}
        for fut in as_completed(futures):
            try:
                if fut.result():
                    return True, futures[fut]
            except Exception:
                continue
    return False, ''


def keepalive_loop(grace: float = KEEPALIVE_GRACE_PERIOD) -> bool:
    """Watch connectivity until either (a) all sites are unreachable
    (return False → caller restarts setup) or (b) the user hits Ctrl+C
    (return True → clean shutdown).

    On entry, sleep `grace` seconds (default KEEPALIVE_GRACE_PERIOD=10s)
    before the first probe -- the tunnel takes a few seconds to come up
    after 登录 success and probing into that window false-positives as
    disconnected. Ctrl+C during the grace period also exits cleanly.

    Cadence: once per KEEPALIVE_PROBE_INTERVAL second, probe ONE random
    URL. Fast path. If that probe fails, fan-out to ALL urls in parallel
    with KEEPALIVE_PROBE_TIMEOUT per request; success of any one means
    the VPN is still alive (one site is just having a hiccup). If the
    burst also returns zero successes, declare the tunnel down.
    """
    import random

    if grace > 0:
        log.info('★ 登录成功, 等 %.0fs 让 VPN 隧道稳定后再开始连通性维护...',
                 grace)
        try:
            time.sleep(grace)
        except KeyboardInterrupt:
            log.info('keepalive: 收到 Ctrl+C (grace 期), 干净退出')
            return True

    log.info('★ 进入连通性维护循环 (%d 站点, %.1fHz probe, %ds timeout/站)',
             len(KEEPALIVE_URLS),
             1.0 / KEEPALIVE_PROBE_INTERVAL,
             KEEPALIVE_PROBE_TIMEOUT)

    try:
        while True:
            url = random.choice(KEEPALIVE_URLS)
            if _probe_url(url):
                log.debug('  keepalive ✓ %s', url)
                time.sleep(KEEPALIVE_PROBE_INTERVAL)
                continue

            log.warning('  keepalive ✗ %s 不通 → 并发探测全部 %d 站',
                        url, len(KEEPALIVE_URLS))
            ok, ok_url = _burst_probe_all()
            if ok:
                log.info('  keepalive ✓ 并发探测中 %s 通过, 连通正常',
                         ok_url)
                time.sleep(KEEPALIVE_PROBE_INTERVAL)
                continue

            log.error('  keepalive ✗ 全部 %d 站点不通, 判定 VPN 掉线, '
                      '触发 setup 重连 (彻底重启 aTrust)',
                      len(KEEPALIVE_URLS))
            return False
    except KeyboardInterrupt:
        log.info('keepalive: 收到 Ctrl+C, 干净退出')
        return True


def click_confirm_connect(main_win, label: str = '[4/4]') -> None:
    """Click '确定接入'.

    Chromium exposes this as a Text element (not Button), same as the top
    tabs. click_input() at the Text's bounding-rect center still triggers
    the underlying <div>'s click handler.
    """
    log.info('%s 点击「确定接入」', label)
    log.debug("locating 确定接入 (Text on access-address panel) ...")
    # First try Text inside the main window.
    cands = wait_for_element(main_win, control_type='Text', text='确定接入',
                             timeout=6.0)
    # Defensive fallback: also accept Button-typed match.
    if not cands:
        log.debug('  no Text found; trying Button 确定接入')
        cands = wait_for_element(main_win, control_type='Button',
                                 text='确定接入', timeout=2.0)
    log.debug('  %d candidate(s) in main window:', len(cands))
    for c in cands:
        log.debug('    %s', _desc(c))
    # Sometimes the action lives in a popup top-level window owned by the
    # same aTrust process. Search those too.
    if not cands:
        pids = _atrust_pids() | {_safe_pid(main_win)}
        for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
            if pid not in pids:
                continue
            try:
                if hasattr(w, 'handle') and hasattr(main_win, 'handle') \
                        and w.handle == main_win.handle:
                    continue
            except Exception:
                pass
            ext = find_inside(w, control_type='Text', text='确定接入') or \
                  find_inside(w, control_type='Button', text='确定接入')
            ext = [c for c in ext if (c.is_visible() and c.is_enabled())]
            if ext:
                log.debug('  found in popup window pid=%d title=%r: %d',
                          pid, title, len(ext))
                cands = ext
                break
    if not cands:
        raise UIATreeReadError("'确定接入' not found anywhere")
    chosen, ok = _pick_actionable(cands, '确定接入')
    log.debug('  -> %s%s', _desc(chosen),
              '' if ok else '  (no actionable; using first)')
    chosen.click_input()
    time.sleep(0.5)


# ---------------------------------------------------------------------------
# Chromium UIA-tree activation + small UIA helpers used by production paths.
# ---------------------------------------------------------------------------

# UIA pattern ID. _LEGACY_PATTERN_ID (= 10018) is the analogous constant for
# the LegacyIAccessible pattern and is defined near _read_toggle_state.
_UIA_ValuePatternId = 10002


def _short(s, n: int = 40) -> str:
    """Truncate `s` to `n` chars with an ellipsis. Used by _uia_soak's
    diagnostic log of the first non-empty UIA element name."""
    if not s:
        return ''
    s = str(s).strip()
    return s if len(s) <= n else s[:n - 1] + '…'


# ----- Chromium UIA tree activation --------------------------------------

import ctypes as _ctypes
from ctypes import wintypes as _wintypes

# user32 with explicit argtypes -- otherwise LPARAM(-4) ends up as
# 0x00000000FFFFFFFC on x64 instead of 0xFFFFFFFFFFFFFFFC, and Chromium /
# CEF silently ignores the WM_GETOBJECT (no tree built).
_user32 = _ctypes.WinDLL('user32', use_last_error=True)
_user32.SendMessageW.argtypes = [
    _wintypes.HWND, _wintypes.UINT, _wintypes.WPARAM, _wintypes.LPARAM,
]
_user32.SendMessageW.restype = _wintypes.LPARAM
_EnumWindowsProc = _ctypes.WINFUNCTYPE(_wintypes.BOOL, _wintypes.HWND, _wintypes.LPARAM)
_user32.EnumWindows.argtypes = [_EnumWindowsProc, _wintypes.LPARAM]
_user32.EnumWindows.restype = _wintypes.BOOL
_user32.EnumChildWindows.argtypes = [
    _wintypes.HWND, _EnumWindowsProc, _wintypes.LPARAM,
]
_user32.EnumChildWindows.restype = _wintypes.BOOL
_user32.SetForegroundWindow.argtypes = [_wintypes.HWND]
_user32.SetForegroundWindow.restype = _wintypes.BOOL
_user32.IsWindow.argtypes = [_wintypes.HWND]
_user32.IsWindow.restype = _wintypes.BOOL
_user32.IsWindowVisible.argtypes = [_wintypes.HWND]
_user32.IsWindowVisible.restype = _wintypes.BOOL
_user32.GetWindowThreadProcessId.argtypes = [
    _wintypes.HWND, _ctypes.POINTER(_wintypes.DWORD),
]
_user32.GetWindowThreadProcessId.restype = _wintypes.DWORD


def _enum_visible_toplevel_hwnds() -> list[int]:
    """Win32 EnumWindows-based fast enumeration of visible top-level HWNDs.
    Returns list[int]. ~10ms on a busy desktop (vs ~1s for
    pywinauto's Desktop(backend='uia').windows())."""
    out: list[int] = []

    @_EnumWindowsProc
    def _cb(hwnd, _):
        if _user32.IsWindowVisible(hwnd):
            out.append(int(hwnd))
        return True

    _user32.EnumWindows(_cb, 0)
    return out


def _hwnd_owner_pid(hwnd: int) -> int:
    pid = _wintypes.DWORD()
    _user32.GetWindowThreadProcessId(hwnd, _ctypes.byref(pid))
    return int(pid.value)

_WM_GETOBJECT     = 0x003D
_OBJID_CLIENT     = -4
_OBJID_NATIVEOM   = -16
_UIA_ROOT_OBJECT  = -25  # UiaRootObjectId


def _enum_descendant_hwnds(parent_hwnd):
    """All descendant HWNDs of parent_hwnd."""
    hwnds = []
    EnumProc = _ctypes.WINFUNCTYPE(_wintypes.BOOL, _wintypes.HWND, _wintypes.LPARAM)

    def cb(h, _l):
        hwnds.append(h)
        return True

    _user32.EnumChildWindows(parent_hwnd, EnumProc(cb), 0)
    return hwnds


def _poke_uia_activate(hwnd) -> int:
    """Tell Chromium / CEF that an accessibility client wants its UIA tree.

    Sends WM_GETOBJECT three times with different object-id LPARAM values:
        UiaRootObjectId  (-25)  -- direct UIA-provider request
        OBJID_CLIENT     (-4)   -- traditional MSAA client area
        OBJID_NATIVEOM   (-16)  -- IAccessible native object model

    Different CEF builds respond to different ones. Returns 1 if at least one
    send succeeded."""
    ok = 0
    for obj_id in (_UIA_ROOT_OBJECT, _OBJID_CLIENT, _OBJID_NATIVEOM):
        try:
            _user32.SendMessageW(hwnd, _WM_GETOBJECT, 0, obj_id)
            ok = 1
        except Exception:
            pass
    return ok


def _force_uia_tree_walk(iuia, window):
    """Drive Chromium / CEF to materialize its DOM accessibility tree.

    Key ingredient (discovered empirically): Chromium only materializes a
    DOM node into UIA when the client reads its LegacyIAccessible.Name --
    not just on ElementFromPoint. So we sweep a small grid of points across
    the window and force property reads on the returned elements.

    Sweep grid is 3x2 (6 points, ~250ms total) -- smaller than the original
    4x3 because each point costs ~40ms (LegacyIAccessible pattern fetch
    crosses COM). The first call materializes the tree; subsequent calls
    are mostly no-ops because Chromium keeps the tree alive once it's been
    asked once.

    Returns FindAll length for diagnostic logging.
    """
    from pywinauto.uia_defines import IUIA
    from ctypes.wintypes import POINT
    LegacyIAccessiblePatternId = 10018
    legacy_iface = IUIA().UIA_dll.IUIAutomationLegacyIAccessiblePattern

    try:
        rect = window.rectangle()
        width = rect.right - rect.left
        height = rect.bottom - rect.top
        for ny in range(2):
            for nx in range(3):
                fx = (nx + 0.5) / 3.0
                fy = (ny + 0.5) / 2.0
                x = int(rect.left + width * fx)
                y = int(rect.top + height * fy)
                try:
                    elem = iuia.ElementFromPoint(POINT(x, y))
                    _ = elem.CurrentName
                    try:
                        pat_obj = elem.GetCurrentPattern(LegacyIAccessiblePatternId)
                        if pat_obj is not None:
                            pat = pat_obj.QueryInterface(legacy_iface)
                            _ = pat.CurrentName
                    except Exception:
                        pass
                except Exception:
                    pass
    except Exception:
        pass

    # Single FindAll for the diagnostic count. Skip the pywinauto descendants
    # walk -- it uses ControlViewWalker which strips Chromium DOM elements
    # anyway, so the count is meaningless and the call is wasted time.
    TreeScope_Subtree = 7
    try:
        raw = window.element_info.element
        true_cond = iuia.CreateTrueCondition()
        found = raw.FindAll(TreeScope_Subtree, true_cond)
        return int(found.Length) if found is not None else 0
    except Exception:
        return 0


def _activate_atrust_uia_trees():
    """Wake up the UIA tree of every visible aTrust-owned top-level window
    (and its child HWNDs), and then force a tree walk so Chromium actually
    populates the DOM mapping."""
    from pywinauto.uia_defines import IUIA
    iuia = IUIA().iuia
    poked_windows = 0
    poked_hwnds = 0
    pids = _atrust_pids()
    targets = []
    for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
        if pid not in pids:
            continue
        try:
            hwnd = int(w.handle)
        except Exception:
            continue
        poked_windows += 1
        poked_hwnds += _poke_uia_activate(hwnd)
        try:
            for ch in _enum_descendant_hwnds(hwnd):
                poked_hwnds += _poke_uia_activate(ch)
        except Exception:
            pass
        targets.append(w)
    # Walking the tree AFTER the poke is the second half of the trick.
    for w in targets:
        _force_uia_tree_walk(iuia, w)
    return poked_windows, poked_hwnds


def _bring_to_foreground(window) -> None:
    """Best-effort: SetForegroundWindow + pywinauto set_focus(). Chromium
    typically wires up its UIA provider only after the window has held
    foreground focus at least once."""
    try:
        hwnd = int(window.handle)
    except Exception:
        return
    if not _user32.IsWindow(hwnd):
        return
    try:
        _user32.SetForegroundWindow(hwnd)
    except Exception:
        pass
    # pywinauto's set_focus does the AttachThreadInput dance which is the
    # only reliable way to take focus from another process on modern Windows.
    try:
        window.set_focus()
    except Exception as e:
        log.debug('set_focus failed (non-fatal): %s', e)


def _uia_soak(window, duration: float = 3.0, min_named: int = 5) -> bool:
    """Drive UIA traffic until Chromium materializes its DOM tree.

    Returns True only when raw FindAll surfaces at least `min_named` elements
    with non-empty names (healthy aTrust shows 30+). Returning True on just
    the root Pane's name -- which IS a named element -- was the previous
    false-positive failure mode.
    """
    from pywinauto.uia_defines import IUIA
    iuia = IUIA().iuia
    window_name = _safe_text(window) or ''
    deadline = time.monotonic() + duration
    iters = 0
    max_raw = 0
    max_named = 0
    while time.monotonic() < deadline:
        raw_count = _force_uia_tree_walk(iuia, window)
        if raw_count > max_raw:
            max_raw = raw_count
        try:
            true_cond = iuia.CreateTrueCondition()
            found = window.element_info.element.FindAll(7, true_cond)
            n = int(found.Length)
            named = 0
            sample_name = ''
            for i in range(n):
                try:
                    nm = (found.GetElement(i).CurrentName or '').strip()
                except Exception:
                    continue
                # Skip the root window's own name -- it's there even when
                # Chromium hasn't built anything below it.
                if not nm or nm == window_name:
                    continue
                named += 1
                if not sample_name:
                    sample_name = nm
                if named >= min_named:
                    log.debug('soak: tree alive (FindAll=%d, named=%d, '
                              'sample=%r)', n, named, _short(sample_name, 24))
                    return True
            if named > max_named:
                max_named = named
        except Exception:
            pass
        iters += 1
        time.sleep(0.1)
    log.warning('soak: tree under-populated after %.1fs '
                '(iters=%d max_FindAll=%d max_named=%d, need %d)',
                duration, iters, max_raw, max_named, min_named)
    return False


def _value_pattern(raw_elem):
    """Read ValuePattern.CurrentValue (typed text in an Edit)."""
    try:
        from pywinauto.uia_defines import IUIA
        pat_obj = raw_elem.GetCurrentPattern(_UIA_ValuePatternId)
        if not pat_obj:
            return ''
        iface = IUIA().UIA_dll.IUIAutomationValuePattern
        pat = pat_obj.QueryInterface(iface)
        return (pat.CurrentValue or '')
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Record mode -- passive listener for human clicks (helpers + entry point)
# ---------------------------------------------------------------------------

# UIA control-type integer -> short string. Only the ones we'll likely see
# in aTrust's UI. Used by the recorder to print human-readable type names.
_UIA_CTYPE = {
    50000: 'Button', 50001: 'Calendar', 50002: 'CheckBox', 50003: 'ComboBox',
    50004: 'Edit',   50005: 'Hyperlink', 50006: 'Image',    50007: 'List',
    50008: 'ListItem', 50009: 'Menu',    50010: 'MenuBar',  50011: 'MenuItem',
    50012: 'ProgressBar', 50013: 'RadioButton', 50014: 'ScrollBar',
    50015: 'Slider', 50016: 'Spinner', 50017: 'StatusBar',  50018: 'Tab',
    50019: 'TabItem', 50020: 'Text',    50021: 'ToolBar',   50022: 'ToolTip',
    50023: 'Tree',   50024: 'TreeItem', 50025: 'Custom',    50026: 'Group',
    50027: 'Thumb',  50028: 'DataGrid', 50029: 'DataItem',  50030: 'Document',
    50031: 'SplitButton', 50032: 'Window', 50033: 'Pane',   50034: 'Header',
    50035: 'HeaderItem', 50036: 'Table',    50037: 'TitleBar',
    50038: 'Separator', 50039: 'SemanticZoom', 50040: 'AppBar',
}


def _legacy_iaccessible(raw_elem):
    """Read LegacyIAccessible pattern properties (name/value/desc/action).
    Returns dict (possibly with empty strings) or None on failure."""
    try:
        from pywinauto.uia_defines import IUIA
        pat_obj = raw_elem.GetCurrentPattern(_LEGACY_PATTERN_ID)
        if not pat_obj:
            return None
        legacy_iface = IUIA().UIA_dll.IUIAutomationLegacyIAccessiblePattern
        pat = pat_obj.QueryInterface(legacy_iface)
        return {
            'name':   (pat.CurrentName or '') if hasattr(pat, 'CurrentName') else '',
            'value':  (pat.CurrentValue or '') if hasattr(pat, 'CurrentValue') else '',
            'desc':   (pat.CurrentDescription or '') if hasattr(pat, 'CurrentDescription') else '',
            'action': (pat.CurrentDefaultAction or '') if hasattr(pat, 'CurrentDefaultAction') else '',
        }
    except Exception:
        return None


def _info_rich(info) -> str:
    """Detailed compact descriptor for one UIA element. Surfaces aria-label
    via LegacyIAccessible + HelpText + AcceleratorKey, all of which Chromium
    populates from ARIA attributes even when UIA Name is blank."""
    try:
        ctype_id = info.control_type
        if isinstance(ctype_id, str):
            ctype = ctype_id
        else:
            ctype = _UIA_CTYPE.get(ctype_id, f'CT{ctype_id}')
    except Exception:
        ctype = '?'

    name    = _short(getattr(info, 'name', '') or '', 32)
    auto_id = _short(getattr(info, 'automation_id', '') or '', 24)
    cls     = _short(getattr(info, 'class_name', '') or '', 24)

    raw = getattr(info, 'element', None)
    help_text = accel = access = item_type = loc_ctype = ''
    legacy_name = legacy_value = legacy_desc = legacy_action = value_pat = ''
    if raw is not None:
        try:    help_text = _short(raw.CurrentHelpText or '', 32)
        except Exception: pass
        try:    accel = _short(raw.CurrentAcceleratorKey or '', 16)
        except Exception: pass
        try:    access = _short(raw.CurrentAccessKey or '', 16)
        except Exception: pass
        try:    item_type = _short(raw.CurrentItemType or '', 16)
        except Exception: pass
        try:    loc_ctype = _short(raw.CurrentLocalizedControlType or '', 16)
        except Exception: pass
        leg = _legacy_iaccessible(raw)
        if leg is not None:
            legacy_name   = _short(leg.get('name', ''),   32)
            legacy_value  = _short(leg.get('value', ''),  32)
            legacy_desc   = _short(leg.get('desc', ''),   32)
            legacy_action = _short(leg.get('action', ''), 16)
        value_pat = _short(_value_pattern(raw), 32)

    parts = [ctype]
    if name:          parts.append(f'name={name!r}')
    if legacy_name and legacy_name != name:
        parts.append(f'legacy_name={legacy_name!r}')
    if value_pat:     parts.append(f'value={value_pat!r}')
    if legacy_value and legacy_value != value_pat:
        parts.append(f'legacy_value={legacy_value!r}')
    if help_text:     parts.append(f'help={help_text!r}')
    if legacy_desc:   parts.append(f'desc={legacy_desc!r}')
    if legacy_action: parts.append(f'action={legacy_action!r}')
    if loc_ctype and loc_ctype != ctype:
        parts.append(f'loc_ctype={loc_ctype!r}')
    if item_type:     parts.append(f'item={item_type!r}')
    if accel:         parts.append(f'accel={accel!r}')
    if access:        parts.append(f'access={access!r}')
    if auto_id:       parts.append(f'auto_id={auto_id!r}')
    elif cls:         parts.append(f'cls={cls!r}')
    return ' '.join(parts)


def _info_short(info) -> str:
    """One-line descriptor used in the parent-chain path."""
    try:
        ctype_id = info.control_type
        if isinstance(ctype_id, str):
            ctype = ctype_id
        else:
            ctype = _UIA_CTYPE.get(ctype_id, f'CT{ctype_id}')
    except Exception:
        ctype = '?'
    name = _short(getattr(info, 'name', '') or '', 24)
    auto_id = _short(getattr(info, 'automation_id', '') or '', 16)
    cls = _short(getattr(info, 'class_name', '') or '', 16)
    parts = [ctype]
    if name:    parts.append(f'{name!r}')
    if auto_id: parts.append(f'id={auto_id}')
    elif cls:   parts.append(f'cls={cls}')
    # Pull legacy_name as a fallback if name is empty.
    if not name:
        raw = getattr(info, 'element', None)
        if raw is not None:
            leg = _legacy_iaccessible(raw)
            if leg and leg.get('name'):
                parts.append(f'legacy={_short(leg["name"], 24)!r}')
    return ' '.join(parts)


def _named_children(info, limit=20):
    """List children of `info` with non-empty UIA name OR legacy name.
    Returns list of compact descriptors."""
    out = []
    try:
        children = info.children()
    except Exception:
        return out
    for c in children:
        try:
            n = (c.name or '').strip()
        except Exception:
            n = ''
        if not n:
            raw = getattr(c, 'element', None)
            if raw is not None:
                leg = _legacy_iaccessible(raw)
                if leg:
                    n = (leg.get('name') or '').strip()
        if n:
            try:
                ctype_id = c.control_type
                ctype = ctype_id if isinstance(ctype_id, str) else _UIA_CTYPE.get(ctype_id, '?')
            except Exception:
                ctype = '?'
            out.append(f'{ctype}:{_short(n, 24)}')
            if len(out) >= limit:
                break
    return out


def _resolve_element_at(iuia, x: int, y: int):
    from ctypes.wintypes import POINT
    from pywinauto.uia_element_info import UIAElementInfo
    try:
        pt = POINT(x, y)
        raw = iuia.ElementFromPoint(pt)
        return UIAElementInfo(raw)
    except Exception:
        return None


def do_record() -> int:
    """Passive recorder for human flow.

    Polls Async key state at 25Hz; on each new LMB/RMB press, resolves the
    UIA element at the cursor and writes a rich descriptor + parent path +
    sibling list to _record.log. Re-pokes the aTrust Chromium UIA trees
    every 5s so a long-idle window doesn't dump its a11y mapping mid-record.
    Ctrl+C exits.
    """
    from ctypes import windll, byref
    from ctypes.wintypes import POINT
    from pywinauto.uia_defines import IUIA

    user32 = windll.user32
    GetAsyncKeyState = user32.GetAsyncKeyState
    GetCursorPos = user32.GetCursorPos
    VK_LBUTTON = 0x01
    VK_RBUTTON = 0x02

    iuia = IUIA().iuia

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '_record.log')
    log_fh = open(log_path, 'w', encoding='utf-8', errors='replace', buffering=1)
    start_t = time.monotonic()

    def emit(msg: str) -> None:
        t = time.monotonic() - start_t
        line = f'T+{t:6.2f}  {msg}'
        print(line, flush=True)
        log_fh.write(line + '\n')

    emit('=== RECORDING STARTED (rich attrs + Chromium UIA wake-up) ===')
    pids = _atrust_pids()
    emit(f'aTrust pids: {sorted(pids)}  ('
         + ', '.join(_proc_name(p) for p in sorted(pids)) + ')')

    known_window_handles: set[int] = set()
    for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
        if pname.lower().startswith('atrust'):
            try:
                h = w.handle
                known_window_handles.add(h)
            except Exception:
                h = 0
            emit(f'INIT_WIN  pid={pid} {pname}  class={cls!r} title={title!r}'
                 f'  rect={rect}')

    # Initial UIA-tree activation.
    wn, hn = _activate_atrust_uia_trees()
    emit(f'WAKE_UIA  poked {hn} HWND(s) across {wn} aTrust window(s)')

    emit('Now perform the manual flow in aTrust UI. Press Ctrl+C to stop.')

    prev_lb = prev_rb = False
    last_win_scan = 0.0
    last_uia_wake = time.monotonic()

    try:
        while True:
            now = time.monotonic()

            # Re-poke every 5s so a long-idle Chromium doesn't dump the tree.
            if now - last_uia_wake > 5.0:
                last_uia_wake = now
                _activate_atrust_uia_trees()

            if now - last_win_scan > 0.6:
                last_win_scan = now
                for w, pid, pname, cls, title, rect in _list_top_level_visible_windows():
                    if not pname.lower().startswith('atrust'):
                        continue
                    try:
                        h = w.handle
                    except Exception:
                        continue
                    if h not in known_window_handles:
                        known_window_handles.add(h)
                        emit(f'NEW_WIN   pid={pid} {pname}  class={cls!r} '
                             f'title={title!r}  rect={rect}')
                        # Wake the newly appeared window too.
                        _poke_uia_activate(int(h))
                        for ch in _enum_descendant_hwnds(int(h)):
                            _poke_uia_activate(ch)

            lb = bool(GetAsyncKeyState(VK_LBUTTON) & 0x8000)
            rb = bool(GetAsyncKeyState(VK_RBUTTON) & 0x8000)

            for label, pressed, was_pressed in (
                ('LMB', lb, prev_lb),
                ('RMB', rb, prev_rb),
            ):
                if pressed and not was_pressed:
                    pt = POINT()
                    GetCursorPos(byref(pt))
                    info = _resolve_element_at(iuia, pt.x, pt.y)
                    if info is None:
                        continue
                    try:
                        pid = info.process_id
                    except Exception:
                        pid = 0
                    pname = _proc_name(pid)
                    pname_l = pname.lower()
                    if not (pname_l.startswith('atrust') or
                            pname_l == 'explorer.exe'):
                        continue

                    # ---- target line (rich) ----
                    emit(f'{label}@({pt.x},{pt.y})  pid={pid} {pname}')
                    emit(f'    target: {_info_rich(info)}')

                    # ---- path (top -> target), short form ----
                    chain = []
                    cur = info
                    for _ in range(10):
                        chain.append(_info_short(cur))
                        try:
                            par = cur.parent
                        except Exception:
                            par = None
                        if par is None:
                            break
                        cur = par
                    path = list(reversed(chain))  # top -> target
                    emit('    path:   ' + '  >  '.join(path))

                    # ---- parent's named children (row anchors) ----
                    try:
                        parent = info.parent
                    except Exception:
                        parent = None
                    if parent is not None:
                        sib_named = _named_children(parent, limit=10)
                        if sib_named:
                            emit(f'    parent.named_children: {sib_named}')

                    # ---- if target resolved only as Document, also dump
                    #      that Document's named children so we can see what
                    #      buttons live in the page ----
                    try:
                        ctype = info.control_type
                        ctype_s = ctype if isinstance(ctype, str) else _UIA_CTYPE.get(ctype, '')
                    except Exception:
                        ctype_s = ''
                    if ctype_s == 'Document':
                        doc_named = _named_children(info, limit=15)
                        if doc_named:
                            emit(f'    document.named_children: {doc_named}')

            prev_lb, prev_rb = lb, rb
            time.sleep(0.04)
    except KeyboardInterrupt:
        emit('=== RECORDING STOPPED (Ctrl+C) ===')
    finally:
        log_fh.close()
        log.info('log saved to %s', log_path)
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Disable abbreviation matching — without this, a bare `--login`
        # would be silently accepted as a prefix of `--login-result-timeout`
        # and then fail with a confusing missing-arg error.
        allow_abbrev=False,
    )
    p.add_argument('--url', default=DEFAULT_URL,
                   help=f'access address to set (default: {DEFAULT_URL})')
    p.add_argument('--test', action='store_true',
                   help='run the full flow with real B-fetched OTP but skip '
                        'the final 登录 click. Use to verify the UI before '
                        'consuming a real login attempt.')
    p.add_argument('--record', action='store_true',
                   help='passive UIA event recorder; logs each aTrust-relevant '
                        'click to _record.log. Ctrl+C to stop.')
    p.add_argument('--b-host', default=DEFAULT_B_HOST,
                   help=f'B host for setup channel (default {DEFAULT_B_HOST})')
    p.add_argument('--b-port', type=int, default=DEFAULT_B_PORT,
                   help=f'B loopback port for setup channel (default {DEFAULT_B_PORT})')
    p.add_argument('--otp-min-remaining', type=int,
                   default=DEFAULT_OTP_MIN_REMAINING,
                   help=f'reject OTP with remaining lifetime <S seconds '
                        f'(default {DEFAULT_OTP_MIN_REMAINING})')
    p.add_argument('--otp-wait-timeout', type=int,
                   default=DEFAULT_OTP_WAIT_TIMEOUT,
                   help=f'max wait for fresh OTP from B in seconds '
                        f'(default {DEFAULT_OTP_WAIT_TIMEOUT})')
    p.add_argument('--pre-login-otp-min', type=int,
                   default=DEFAULT_PRE_LOGIN_OTP_MIN,
                   help=f'AFTER typing the OTP but BEFORE clicking 登录, '
                        f'recheck OTP freshness with B; if remaining drops '
                        f'below S seconds (or B has rotated to a new code), '
                        f'fetch a fresh OTP and retype. '
                        f'(default {DEFAULT_PRE_LOGIN_OTP_MIN})')
    p.add_argument('--login-result-timeout', type=int,
                   default=DEFAULT_LOGIN_RESULT_TIMEOUT,
                   help=f'max wait for login outcome in seconds '
                        f'(default {DEFAULT_LOGIN_RESULT_TIMEOUT})')
    p.add_argument('--keepalive-url', action='append', default=[],
                   help='intranet URL to probe for VPN liveness. Provide '
                        'one URL per flag, repeatable. Override the '
                        'placeholder defaults built into the script.')
    p.add_argument('--verbose', action='store_true',
                   help='DEBUG-level logs + per-phase tree dumps')
    return p.parse_args()


def _run_setup_once(args) -> int:
    """One pass through the attach + 9-step UI flow. Returns:
        0 = success: login confirmed (production), OR steps 1-8 + OTP
            freshness all passed (--test)
        1 = login result was 'failure' (wrong creds / locked account)
            -- the caller MUST NOT retry, or it burns the failure counter
        2 = unknown: post-login result inconclusive (neither
            success_card nor failure within login-result-timeout)
        3 = UI flow crashed mid-step (UIATreeReadError or any other
            exception in Phase 1 / Phase 2) -- caller SHOULD retry up to
            MAX_UIA_RETRIES with a fresh aTrust launch
        4 = attach_or_launch itself failed (couldn't spawn aTrust or pin
            its main window) -- also retryable

    Pre-flight (B reachable, EXE present) is the caller's responsibility
    — it's idempotent + one-time so doing it on every retry just wastes
    log lines. attach_or_launch always kills + relaunches aTrust, so this
    function is safe to call repeatedly for keepalive-driven reconnects.
    """
    try:
        main_win = attach_or_launch()
    except Exception as e:
        log.error('attach_or_launch failed: %s', e)
        traceback.print_exc()
        return 4

    win_pid = _safe_pid(main_win)
    win_proc = _proc_name(win_pid)
    log.debug('main window pinned: pid=%d proc=%s class=%r title=%r',
              win_pid, win_proc, _safe_class(main_win), _safe_text(main_win))
    if not win_proc.lower().startswith('atrust'):
        log.error('SAFETY: chosen main window pid=%d proc=%s is NOT an '
                  'aTrust process. Aborting before any clicks happen.',
                  win_pid, win_proc)
        return 1

    # attach_or_launch already started aTrust fresh; just wake its UIA tree
    # and confirm the DOM materialized.
    main_win = ensure_healthy_ui(main_win)

    if args.verbose:
        log.debug('--- tree under main window (after attach) ---')
        dump_tree(main_win, max_depth=4)

    # Step-label total:
    #   default -> 9 (phase 1 + phase 2 incl. 登录 + result detect)
    #   --test  -> 8 (same as default through step 8, skip 登录 + detect)
    total = 8 if args.test else 9
    L = lambda n: f'[{n}/{total}]'

    # If aTrust opened directly onto the login form (prior session
    # remembered the access URL + auto-resumed connection state), Phase 1
    # is a no-op -- the URL panel isn't even reachable from here without
    # backing out. Skip steps 1-4 and let Phase 2's wait_for_login_form
    # confirm the form is actually usable.
    if _is_at_login_form(main_win):
        log.info('启动后已位于登录页 (Edit「请输入账号」可见), '
                 '跳过 Phase 1 (步骤 [1-4])')
    else:
        # ----- Phase 1: access-address configuration ---------------------
        try:
            click_settings(main_win, label=L(1))
            if args.verbose:
                log.debug('--- tree after 设置 ---')
                dump_tree(main_win, max_depth=4)

            click_switch_in_access_row(main_win, label=L(2))
            if args.verbose:
                log.debug('--- tree after 切换 ---')
                dump_tree(main_win, max_depth=4)

            set_access_url(main_win, args.url, label=L(3))
            if args.verbose:
                log.debug('--- tree after URL entry ---')
                dump_tree(main_win, max_depth=4)

            click_confirm_connect(main_win, label=L(4))
        except Exception as e:
            log.error('step failed: %s', e)
            traceback.print_exc()
            log.info('--- current tree under main window for debugging ---')
            try:
                dump_tree(main_win, max_depth=5)
            except Exception:
                pass
            return 3

    # ----- Phase 2: login (default) / login-up-to-step-8 (--test) --------
    try:
        log.info('%s 等待登录页 + 取 OTP', L(5))
        main_win = wait_for_login_form(main_win, timeout=30.0)

        # Fetch fresh OTP from B for both modes. --test only differs from
        # default at the very end (skip the 登录 click).
        otp_data, remaining = fetch_fresh_otp(
            args.b_host, args.b_port,
            min_remaining=args.otp_min_remaining,
            timeout=args.otp_wait_timeout,
        )
        username = otp_data.get('username', '') or ''
        otp_code = otp_data.get('code', '') or ''
        if not username or not otp_code:
            raise RuntimeError(
                f'B returned malformed otp_state (username={username!r}, '
                f'has_code={bool(otp_code)})'
            )
        log.info('  -> 拿到 OTP: user=%s, remaining=%.1fs',
                 username, remaining)

        check_terms_checkbox(main_win, label=L(6))
        type_username(main_win, username, label=L(7))

        # Step 8: type OTP + post-type freshness recheck. Loop until the
        # typed OTP both (a) lands correctly (input length verified inside
        # _type_per_char) AND (b) is still B's current code with
        # >=--pre-login-otp-min seconds of remaining life. Otherwise
        # fetch a NEW OTP (waiting up to one TOTP period for B's cache
        # to rotate) and retype. Caps at MAX_OTP_TYPE_ATTEMPTS retries
        # so a persistently degraded UI doesn't loop forever.
        otp_attempt = 0
        while True:
            otp_attempt += 1
            label = L(8) if otp_attempt == 1 else f'{L(8)} (retry {otp_attempt - 1})'
            type_password(main_win, otp_code, label=label)

            fresh, info = check_typed_otp_still_fresh(
                args.b_host, args.b_port, otp_code,
                min_remaining=args.pre_login_otp_min,
            )
            if fresh:
                log.info('  OTP 输入后新鲜度校验通过 (%s)', info)
                break
            log.warning('  OTP 输入后新鲜度校验失败 (%s); 取下一轮 OTP 重输',
                        info)
            if otp_attempt >= MAX_OTP_TYPE_ATTEMPTS:
                raise RuntimeError(
                    f'OTP 输入+校验循环 {MAX_OTP_TYPE_ATTEMPTS} 次仍未通过 '
                    f'(最后一次: {info}); 放弃 — 检查 typing 耗时或 B 状态'
                )
            otp_data, remaining = fetch_fresh_otp(
                args.b_host, args.b_port,
                min_remaining=args.otp_min_remaining,
                timeout=args.otp_wait_timeout,
            )
            otp_code = otp_data.get('code', '') or ''
            if not otp_code:
                raise RuntimeError(
                    f'B refresh malformed otp_state: {otp_data}'
                )
            log.info('  -> 新一轮 OTP 到手, remaining=%.1fs (attempt %d)',
                     remaining, otp_attempt + 1)

        # OTP loop above has confirmed: typed code matches B's current,
        # and remaining >= --pre-login-otp-min. Now safe to click 登录.
        if args.test:
            log.info('完成 (test): 步骤 1-8 + OTP 新鲜度均通过 '
                     '(%d 次输入), 未点击「登录」。', otp_attempt)
            return 0

        # Snapshot BEFORE clicking — used to compute new-Texts diff.
        baseline_texts = _snapshot_named_elements(main_win)
        baseline_handles = _atrust_toplevel_handles()
        log.debug('  baseline: %d named texts, %d aTrust windows',
                  len(baseline_texts), len(baseline_handles))

        click_login(main_win, label=L(9))

        result, detail = check_login_result(
            main_win, baseline_texts, baseline_handles,
            timeout=args.login_result_timeout,
        )
    except Exception as e:
        log.error('login step failed: %s', e)
        traceback.print_exc()
        log.info('--- current tree under main window for debugging ---')
        try:
            dump_tree(main_win, max_depth=5)
        except Exception:
            pass
        return 3

    if result.startswith('success'):
        suffix = f' ({detail!r})' if detail else ''
        log.info('完成: 登录成功 [%s]%s', result, suffix)
        return 0
    if result == 'failure':
        log.error('登录失败: %s', detail)
        # IMPORTANT: do NOT retry on failure — aTrust has a finite
        # failure-count limit before locking the account. The operator
        # should inspect _setup.log and the aTrust state manually before
        # invoking this script again.
        return 1
    log.warning('登录结果未知: %ds 内既未关窗也未见错误/成功提示。'
                '请人工检查 aTrust 状态。', args.login_result_timeout)
    return 2


def main() -> int:
    args = parse_args()

    # --verbose flips the root logger to DEBUG, surfacing all the per-step
    # candidate lists, UIA wake/soak diagnostics, and tree dumps.
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.test and args.record:
        log.error('--test and --record are mutually exclusive')
        return 2

    # --record: passive recorder only, no aTrust UI driving.
    if args.record:
        return do_record()

    # Override the placeholder KEEPALIVE_URLS with the operator-supplied
    # intranet probe set, if any. This is the ONLY way connectivity
    # checks actually mean something — the defaults are not real hosts.
    if args.keepalive_url:
        global KEEPALIVE_URLS
        KEEPALIVE_URLS = tuple(args.keepalive_url)

    mode_tag = '  [+test, no 登录 click]' if args.test else ''
    log.info('启动 atrust_setup  URL=%s%s', args.url, mode_tag)

    if not os.path.exists(EXE):
        log.error('aTrustTray.exe not found at: %s', EXE)
        return 2

    # Pre-flight (one-time): B must be reachable before we kick off
    # aTrust. If we skip this and start the UI flow first, a B-not-running
    # condition would only surface at step [5/8] after we've already
    # restarted the user's aTrust + walked the URL-config UI, wasting
    # 10+ seconds and disrupting any active VPN session for nothing.
    log.info('Pre-flight: 检查 B 是否可达 (%s:%d)...',
             args.b_host, args.b_port)
    ok, status = verify_b_reachable(args.b_host, args.b_port)
    if not ok:
        log.error('Module B 不可达 (%s).', status)
        log.error('请先启动 B: bash run_b.sh  (或本机联调: bash run.sh)')
        return 2
    log.info('  -> B reachable (%s)', status)

    # Outer loop. Per iteration (production):
    #   1. Pre-setup probe (Phase 0): concurrently test all KEEPALIVE_URLS.
    #      If ANY is reachable, the VPN tunnel is already up -- skip the
    #      whole aTrust UI flow and jump straight into keepalive with
    #      grace=0 (no need to wait for a tunnel that's already up).
    #   2. Otherwise run _run_setup_once (kill+relaunch aTrust + Phase 1
    #      + Phase 2 + 登录), then keepalive with default 10s grace.
    #   3. keepalive returns True (Ctrl+C) → exit; False (disconnect) →
    #      next iteration. Skip the next Phase 0 probe ONLY when
    #      keepalive's own burst-probe-all is what tripped the disconnect
    #      (skip_pre_probe=True) -- re-probing the same sites <1s later
    #      would just waste ~3s confirming what we know. A Phase-0
    #      short-circuit followed by keepalive disconnect, by contrast,
    #      DOES re-probe: that disconnect was based on a single random
    #      probe miss, not the burst.
    # In --test mode we skip Phase 0 entirely (test exists to exercise
    # the aTrust UI flow) and run setup once.
    setup_iter = 0
    skip_pre_probe = False  # True iff keepalive's burst just confirmed
                            # a full disconnect — next iter goes straight
                            # to setup without redoing the same probe
    while True:
        setup_iter += 1

        if not args.test:
            if skip_pre_probe:
                log.info('=== Iter %d: keepalive 刚判定 %d 站全断, '
                         '跳过冗余 Phase 0 探测, 直接 setup ===',
                         setup_iter, len(KEEPALIVE_URLS))
                skip_pre_probe = False
            else:
                log.info('=== Iter %d: 自动化前并发探测连通性 '
                         '(%d 站点, %ds/站) ===',
                         setup_iter, len(KEEPALIVE_URLS),
                         KEEPALIVE_PROBE_TIMEOUT)
                already_up, hit_url = _burst_probe_all()
                if already_up:
                    log.info('  ✓ VPN 已连通 (%s 可达), 跳过 aTrust 自动化, '
                             '直接进入连通性维护', hit_url)
                    if keepalive_loop(grace=0):
                        return 0
                    # Phase-0-shortcircuit → keepalive disconnect:
                    # keepalive's final state was burst-probe-all failed,
                    # so skipping the next Phase 0 is safe.
                    skip_pre_probe = True
                    continue
                log.info('  ✗ 全部 %d 站点不通, 进入 setup 自动化流程',
                         len(KEEPALIVE_URLS))

        # Inner retry loop: rc 3 (UI step crashed) / rc 4 (attach failed)
        # are retryable -- attach_or_launch in the next call kills +
        # relaunches aTrust, giving the Chromium UIA tree a fresh chance
        # to materialize. rc 1 (login result == failure) must NOT retry:
        # that's wrong-credential / locked-account territory, and looping
        # would burn the failure counter and mask the root cause.
        uia_retries = 0
        while True:
            rc = _run_setup_once(args)
            if rc in (3, 4) and uia_retries < MAX_UIA_RETRIES:
                uia_retries += 1
                log.warning(
                    'UI 失败 (rc=%d) — 杀掉 aTrust 进程并重试 (%d/%d)',
                    rc, uia_retries, MAX_UIA_RETRIES,
                )
                # Explicit kill + cooldown. _run_setup_once's
                # attach_or_launch already kills, but doing it here too
                # ensures the OS process state has settled before the
                # next launch — avoids the "fresh launch attaches to
                # a still-dying instance" race.
                try:
                    _kill_all_atrust_tray()
                except Exception:
                    pass
                time.sleep(1.5)
                continue
            break
        if rc != 0:
            return rc
        if args.test:
            # Test mode: one pass, no keepalive, exit clean.
            return 0
        # Production + successful login: hold the line. Default grace
        # (10s) gives the freshly-established tunnel time to settle.
        if keepalive_loop():
            # Ctrl+C: clean shutdown, do not reconnect.
            return 0
        # Setup-completed → keepalive → disconnect: it just did
        # burst-probe-all that failed; skip the next iteration's
        # Phase 0 probe to avoid duplicating that check.
        skip_pre_probe = True


if __name__ == '__main__':
    sys.exit(main())
