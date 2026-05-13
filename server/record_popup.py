"""record_popup.py — diagnose the aTrust login-success popup.

Standalone recorder: figures out which window the success popup actually
is, so check_login_result in atrust_setup.py can be taught the right
selectors.

Two parallel signal sources:

  (a) Window-appearance watcher.
      Polls every 200ms for new visible top-level windows owned by ANY
      process. When a new one appears, dumps full attributes:
        pid, process name, exe path, window class, UIA name, window title,
        rect, full named-UIA-descendant tree (Text/Button/Hyperlink/...).

  (b) Click-target sniffer.
      Polls VK_LBUTTON / VK_RBUTTON state at 25Hz. On each press-edge,
      uses IUIAutomation::ElementFromPoint to identify what the user
      clicked, walks up to the owning top-level window, and dumps the
      same attribute set.

Both write to _record.log alongside terminal output.

Usage:
  1. Start B + setup as usual (e.g.  bash run_local.sh  with login).
  2. In a SECOND shell:  python record_popup.py
  3. Trigger the login on the main shell. When the success popup
     appears, click it. The recorder logs both:
       — the window appearing automatically (signal a)
       — your click confirming which one it is (signal b)
  4. Ctrl+C to stop. Send _record.log over.

We need to learn:
  • Is the popup owned by an aTrust*.exe process, or by a system shell
    (explorer.exe / ApplicationFrameHost.exe / ShellExperienceHost.exe /
    Microsoft.WindowsNotificationCenter etc.)?
  • What is its window class (Chrome_WidgetWin_1? Windows.UI.Core.CoreWindow?
    NotifyIconOverflowWindow?)?
  • What text does it actually contain (so we can match the right
    SUCCESS_CARD_KEYWORDS)?
"""

from __future__ import annotations

import os
import sys
# Add sibling `shared/` to sys.path so `_paths` resolves.
_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared')
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import ctypes
import time
from ctypes import byref, wintypes

try:
    import psutil
except ImportError as e:
    print(f'pip install psutil  ({e})', file=sys.stderr)
    sys.exit(2)

try:
    from pywinauto.uia_defines import IUIA
    from pywinauto.uia_element_info import UIAElementInfo
except ImportError as e:
    print(f'pip install pywinauto  ({e})', file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Win32 bindings
# ---------------------------------------------------------------------------

user32   = ctypes.WinDLL('user32',   use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes              = [EnumWindowsProc, wintypes.LPARAM]
user32.EnumWindows.restype               = wintypes.BOOL
user32.IsWindowVisible.argtypes          = [wintypes.HWND]
user32.IsWindowVisible.restype           = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype  = wintypes.DWORD
user32.GetClassNameW.argtypes            = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.restype             = ctypes.c_int
user32.GetWindowTextW.argtypes           = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype            = ctypes.c_int
user32.GetWindowRect.argtypes            = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowRect.restype             = wintypes.BOOL
user32.GetAncestor.argtypes              = [wintypes.HWND, ctypes.c_uint]
user32.GetAncestor.restype               = wintypes.HWND
user32.WindowFromPoint.argtypes          = [wintypes.POINT]
user32.WindowFromPoint.restype           = wintypes.HWND
user32.GetCursorPos.argtypes             = [ctypes.POINTER(wintypes.POINT)]
user32.GetCursorPos.restype              = wintypes.BOOL
user32.GetAsyncKeyState.argtypes         = [ctypes.c_int]
user32.GetAsyncKeyState.restype          = wintypes.SHORT

_GA_ROOT = 2


# ---------------------------------------------------------------------------
# UIA control-type id → short name. Recorder-only; kept here for symmetry
# with atrust_setup.py's old _UIA_CTYPE (no longer needed by production).
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

import _paths
_paths.ensure_dirs()
LOG_PATH = _paths.LOG_RECORD

_log_fh = open(LOG_PATH, 'w', encoding='utf-8', errors='replace', buffering=1)
_start_t = time.monotonic()


def emit(msg: str = '') -> None:
    t = time.monotonic() - _start_t
    line = f'T+{t:7.2f}  {msg}' if msg else ''
    print(line, flush=True)
    _log_fh.write(line + '\n')


def _short(s: str, n: int = 60) -> str:
    if not s:
        return ''
    return s if len(s) <= n else s[: n - 1] + '…'


# ---------------------------------------------------------------------------
# Window introspection
# ---------------------------------------------------------------------------

def enum_visible_toplevel_hwnds() -> list[int]:
    out: list[int] = []

    @EnumWindowsProc
    def _cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            out.append(int(hwnd))
        return True

    user32.EnumWindows(_cb, 0)
    return out


def hwnd_class(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def hwnd_title(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


def hwnd_rect(hwnd: int) -> str:
    r = wintypes.RECT()
    if user32.GetWindowRect(hwnd, byref(r)):
        return f'(L{r.left}, T{r.top}, R{r.right}, B{r.bottom})  ' \
               f'{r.right - r.left}x{r.bottom - r.top}'
    return '<no rect>'


def hwnd_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, byref(pid))
    return int(pid.value)


def proc_info(pid: int) -> tuple[str, str]:
    """(name, exe) — or (name, '<error>') if psutil can't read."""
    try:
        p = psutil.Process(pid)
        return p.name(), p.exe()
    except Exception as e:
        return '<unknown>', f'<error: {e}>'


def uia_named_descendants(hwnd: int, cap: int = 60) -> list[str]:
    """All named UIA descendants of a top-level HWND. Returns
    compact one-line descriptors."""
    out: list[str] = []
    try:
        iuia = IUIA().iuia
        root_elem = iuia.ElementFromHandle(hwnd)
        true_cond = iuia.CreateTrueCondition()
        found = root_elem.FindAll(7, true_cond)  # TreeScope_Subtree
        n = int(found.Length)
    except Exception as e:
        return [f'<UIA enum failed: {e}>']

    for i in range(min(n, cap)):
        try:
            e = found.GetElement(i)
            name = (e.CurrentName or '').strip()
            if not name:
                continue
            ct = _UIA_CTYPE.get(e.CurrentControlType, f'CT{e.CurrentControlType}')
            cls = (getattr(e, 'CurrentClassName', '') or '')
            auto_id = (getattr(e, 'CurrentAutomationId', '') or '')
            tail = ''
            if auto_id:
                tail = f'  id={_short(auto_id, 24)!r}'
            elif cls:
                tail = f'  cls={_short(cls, 24)!r}'
            out.append(f'{ct}:{_short(name, 48)!r}{tail}')
        except Exception:
            continue
    if n > cap:
        out.append(f'... ({n - cap} more truncated)')
    return out


def dump_window(hwnd: int, marker: str) -> None:
    pid = hwnd_pid(hwnd)
    pname, pexe = proc_info(pid)
    emit(f'{marker} HWND=0x{hwnd:08x}  pid={pid}  proc={pname}')
    emit(f'      exe={pexe}')
    emit(f'      class={hwnd_class(hwnd)!r}')
    emit(f'      title={hwnd_title(hwnd)!r}')
    emit(f'      rect={hwnd_rect(hwnd)}')
    named = uia_named_descendants(hwnd)
    if named:
        emit(f'      named UIA descendants ({len(named)}):')
        for line in named:
            emit(f'        - {line}')
    else:
        emit('      (no named UIA descendants)')


# ---------------------------------------------------------------------------
# Click-target identification
# ---------------------------------------------------------------------------

def hwnd_at_cursor() -> int:
    pt = wintypes.POINT()
    user32.GetCursorPos(byref(pt))
    h = user32.WindowFromPoint(pt)
    if not h:
        return 0
    # Walk up to the top-level window owning the click.
    top = user32.GetAncestor(h, _GA_ROOT)
    return int(top) if top else int(h)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> int:
    emit('=== record_popup STARTED ===')
    emit(f'log file: {LOG_PATH}')
    emit('')
    emit('--- initial visible top-level windows ---')
    initial = enum_visible_toplevel_hwnds()
    emit(f'count: {len(initial)}')
    known = set()
    for h in initial:
        try:
            pid = hwnd_pid(h)
            pname, _ = proc_info(pid)
            cls = hwnd_class(h)
            title = hwnd_title(h)
            emit(f'  HWND=0x{h:08x}  pid={pid}  proc={pname:24s}  '
                 f'class={cls!r}  title={_short(title, 40)!r}')
        except Exception as e:
            emit(f'  HWND=0x{h:08x}  <error: {e}>')
        known.add(h)
    emit('')
    emit('Now: trigger the aTrust login. When the success popup appears,')
    emit('CLICK ON IT (left-mouse). Both the appearance event and your')
    emit('click are logged. Ctrl+C to stop.')
    emit('')

    VK_LBUTTON = 0x01
    VK_RBUTTON = 0x02
    prev_lb = False
    prev_rb = False
    last_poll = 0.0

    try:
        while True:
            now = time.monotonic()

            # ---- (a) window-appearance watcher ----
            if now - last_poll > 0.2:
                last_poll = now
                current = enum_visible_toplevel_hwnds()
                new_h = [h for h in current if h not in known]
                gone_h = [h for h in known if h not in current]
                for h in new_h:
                    known.add(h)
                    emit('>>> NEW WINDOW APPEARED <<<')
                    dump_window(h, marker='  NEW')
                    emit('')
                for h in gone_h:
                    known.discard(h)
                    emit(f'<<< WINDOW GONE  HWND=0x{h:08x}')
                    emit('')

            # ---- (b) click sniffer ----
            lb = bool(user32.GetAsyncKeyState(VK_LBUTTON) & 0x8000)
            rb = bool(user32.GetAsyncKeyState(VK_RBUTTON) & 0x8000)
            for label, pressed, was_pressed in (
                ('LMB', lb, prev_lb),
                ('RMB', rb, prev_rb),
            ):
                if pressed and not was_pressed:
                    pt = wintypes.POINT()
                    user32.GetCursorPos(byref(pt))
                    top = hwnd_at_cursor()
                    if top:
                        emit(f'### {label} CLICK @ ({pt.x},{pt.y}) → top-level '
                             f'HWND=0x{top:08x}')
                        try:
                            dump_window(top, marker='  CLICK')
                        except Exception as e:
                            emit(f'  CLICK dump failed: {e}')
                        emit('')
                    else:
                        emit(f'### {label} CLICK @ ({pt.x},{pt.y}) — no top-level under cursor')
                        emit('')
            prev_lb, prev_rb = lb, rb

            time.sleep(0.04)
    except KeyboardInterrupt:
        emit('=== record_popup STOPPED (Ctrl+C) ===')
    finally:
        try:
            _log_fh.close()
        except Exception:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
