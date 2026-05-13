#!/usr/bin/env bash
# run_test_seperate.sh — separated TEST on the B host.
#
# Same as run_b.sh BUT setup stops short of clicking 登录, and the
# workers stay strictly foreground (Ctrl+B rejected). Pair with
# run_a.sh on the A host (no separate test variant for A -- A's flow
# has nothing irreversible to test-skip).
#
# Uses the Python modules' built-in port defaults. To run against a
# remote A with non-default ports, set env vars before invoking:
#   LISTEN_PORT=N PEER_PORT=N PEER_HOST=<A IP> bash run_test_seperate.sh
#
# TEST RULES:
#   - 2 workers (B + setup) foreground; Ctrl+B disabled.
#   - Ctrl+C tears everything down.

set -e
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

source "$REPO/_paths.sh"
ensure_dirs
source "$REPO/shared/_runner.sh"

PY=
for _cand in python python3; do
    if command -v "$_cand" >/dev/null 2>&1; then
        if "$_cand" -c 'import sys; print(sys.version_info[0])' 2>/dev/null | grep -q '^3'; then
            PY=$_cand; break
        fi
    fi
done
[ -n "$PY" ] || { echo "[error] no working python on PATH" >&2; exit 1; }

need_pkgs=()
$PY -c 'import requests'     2>/dev/null || need_pkgs+=("requests")
$PY -c 'import cryptography'  2>/dev/null || need_pkgs+=("cryptography")
$PY -c 'import pywinauto'    2>/dev/null || need_pkgs+=("pywinauto")
$PY -c 'import psutil'       2>/dev/null || need_pkgs+=("psutil")
if [ ${#need_pkgs[@]} -gt 0 ]; then
    echo "[test-sep] pip install ${need_pkgs[*]} ..."
    pip install --quiet --disable-pip-version-check "${need_pkgs[@]}"
fi

NEW_LINK_CERT=no
if [ ! -f "$CERT_LINK_CRT" ] || [ ! -f "$CERT_LINK_KEY" ]; then
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_cert()'
    NEW_LINK_CERT=yes
fi
if [ ! -f "$CERT_LOCAL_CRT" ] || [ ! -f "$CERT_LOCAL_KEY" ]; then
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_local_cert()'
fi
if [ "$NEW_LINK_CERT" = "yes" ]; then
    echo "[test-sep] IMPORTANT: copy $CERT_LINK_CRT + $CERT_LINK_KEY to the A host (\$CERTS_DIR)"
fi

ATRUST_EXE="C:/Program Files (x86)/Sangfor/aTrust/aTrustTray/aTrustTray.exe"
[ -f "$ATRUST_EXE" ] || { echo "[error] aTrust not installed" >&2; exit 2; }

# Stop leftovers
_runner_init
_runner_register B     "$PID_B"     "$LOG_B"
_runner_register setup "$PID_SETUP" "$LOG_SETUP"
_runner_kill_all >/dev/null 2>&1 || true
sleep 0.3

echo "[test-sep] ★ TEST MODE: B + setup foreground, Ctrl+B disabled"
echo "[test-sep]              setup walks steps 1-8 + OTP-fresh check, NO 登录 click"

_runner_spawn B     "$PID_B"     "$LOG_B"     "$REPO/server/otp_poller.py"
sleep 0.6
_runner_spawn setup "$PID_SETUP" "$LOG_SETUP" "$REPO/server/atrust_setup.py" \
    --test --b-host 127.0.0.1 --b-port 7001

_runner_attach --foreground-only
