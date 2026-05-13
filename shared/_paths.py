"""Centralized runtime path definitions for the VPN automation stack.

Why this module exists: the repo itself stays free of per-user state
and secrets. All runtime artifacts (TLS certs, logs, PID files, capture
flag, proxy backup) live OUTSIDE the project directory under a single
data dir picked at import time:

    Windows:  %APPDATA%\\atrust-vpn   (typically C:\\Users\\<u>\\AppData\\Roaming\\atrust-vpn)
    POSIX:    ~/.atrust-vpn

Override the base via the ATRUST_VPN_DATA environment variable (useful
for tests / CI / sandboxed runs).

Layout under DATA_DIR:
    certs/
        link.crt, link.key       # A<->B mutual TLS pair. The .crt + .key
                                 # are generated on B and copied to A.
        local.crt, local.key     # B<->setup loopback pair. Generated on
                                 # B; NEVER leaves the B host.
    logs/
        a.log, b.log, setup.log, mitm.log, record.log
    state/
        a.pid, b.pid, setup.pid       # PID files for the launchers
        capture.flag                  # mitm capture-mode toggle
        proxy_backup.json             # original HKCU proxy, restored on exit

Idempotently call `ensure_dirs()` before writing to any of these paths.
"""

from __future__ import annotations

import os


def _default_data_dir() -> str:
    override = os.environ.get('ATRUST_VPN_DATA')
    if override:
        return os.path.abspath(os.path.expanduser(override))
    if os.name == 'nt':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
        return os.path.join(base, 'atrust-vpn')
    return os.path.join(os.path.expanduser('~'), '.atrust-vpn')


DATA_DIR  = _default_data_dir()
CERTS_DIR = os.path.join(DATA_DIR, 'certs')
LOGS_DIR  = os.path.join(DATA_DIR, 'logs')
STATE_DIR = os.path.join(DATA_DIR, 'state')

# --- TLS certs (generated lazily by _link.ensure_cert / ensure_local_cert)
CERT_LINK_CRT  = os.path.join(CERTS_DIR, 'link.crt')
CERT_LINK_KEY  = os.path.join(CERTS_DIR, 'link.key')
CERT_LOCAL_CRT = os.path.join(CERTS_DIR, 'local.crt')
CERT_LOCAL_KEY = os.path.join(CERTS_DIR, 'local.key')

# --- Logs
LOG_A      = os.path.join(LOGS_DIR, 'a.log')
LOG_B      = os.path.join(LOGS_DIR, 'b.log')
LOG_SETUP  = os.path.join(LOGS_DIR, 'setup.log')
LOG_MITM   = os.path.join(LOGS_DIR, 'mitm.log')
LOG_RECORD = os.path.join(LOGS_DIR, 'record.log')

# --- State
PID_A          = os.path.join(STATE_DIR, 'a.pid')
PID_B          = os.path.join(STATE_DIR, 'b.pid')
PID_SETUP      = os.path.join(STATE_DIR, 'setup.pid')
CAPTURE_FLAG   = os.path.join(STATE_DIR, 'capture.flag')
PROXY_BACKUP   = os.path.join(STATE_DIR, 'proxy_backup.json')


def ensure_dirs() -> None:
    """Create DATA_DIR + the three sub-dirs (certs/logs/state). Idempotent."""
    for d in (DATA_DIR, CERTS_DIR, LOGS_DIR, STATE_DIR):
        os.makedirs(d, exist_ok=True)


if __name__ == '__main__':
    # Diagnostic: dump the resolved paths so callers (bash scripts) can
    # confirm what's actually in effect under their env.
    print(f'DATA_DIR  = {DATA_DIR}')
    print(f'CERTS_DIR = {CERTS_DIR}')
    print(f'LOGS_DIR  = {LOGS_DIR}')
    print(f'STATE_DIR = {STATE_DIR}')
