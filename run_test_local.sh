#!/usr/bin/env bash
# run_test_local.sh — local TEST: A + B + setup all on this machine.
#
# Setup walks steps 1..8 (terms + username + OTP input) and verifies OTP
# freshness, but stops short of clicking 登录. Otherwise identical to
# production: A captures the cookie, B polls /otp, setup drives aTrust UI.
#
# Mirrors run_b.sh's B-related pre-flight + spawn logic; only difference
# is that A is colocated and setup runs with --test (skip 登录 click).
#
# Uses the Python modules' built-in default ports for the loopback test
# (mitm_capture.py and otp_poller.py have distinct LISTEN_PORT defaults so
# A and B don't collide on the same env in the shared parent shell).
#
# TEST RULES:
#   - All three workers stay foreground (Ctrl+B is REJECTED).
#   - Ctrl+C tears everything down.
#   - No PIDs survive past this script's exit.

set -e
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

source "$REPO/_paths.sh"
ensure_dirs
source "$REPO/shared/_runner.sh"

# ----- pre-flight (identical to run_a.sh + run_b.sh deps) ---------------
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
$PY -c 'import requests'      2>/dev/null || need_pkgs+=("requests")
$PY -c 'import cryptography'   2>/dev/null || need_pkgs+=("cryptography")
$PY -c 'import mitmproxy'     2>/dev/null || need_pkgs+=("mitmproxy")
$PY -c 'import pywinauto'     2>/dev/null || need_pkgs+=("pywinauto")
$PY -c 'import psutil'        2>/dev/null || need_pkgs+=("psutil")
if [ ${#need_pkgs[@]} -gt 0 ]; then
    echo "[test-local] pip install ${need_pkgs[*]} ..."
    pip install --quiet --disable-pip-version-check "${need_pkgs[@]}"
fi

# Cert pairs (same as run_b.sh — link.crt for A↔B, local.crt for B↔setup)
if [ ! -f "$CERT_LINK_CRT" ] || [ ! -f "$CERT_LINK_KEY" ]; then
    echo "[test-local] generating A<->B cert pair (link.crt/link.key)..."
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_cert()'
fi
if [ ! -f "$CERT_LOCAL_CRT" ] || [ ! -f "$CERT_LOCAL_KEY" ]; then
    echo "[test-local] generating B<->setup cert pair (local.crt/local.key)..."
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_local_cert()'
fi

ATRUST_EXE="C:/Program Files (x86)/Sangfor/aTrust/aTrustTray/aTrustTray.exe"
[ -f "$ATRUST_EXE" ] || { echo "[error] aTrust not installed" >&2; exit 2; }

# mitmproxy CA install (only test_local needs it — A is colocated)
ca_trusted=$(powershell -NoProfile -ExecutionPolicy Bypass \
    -File "$REPO/shared/_env.ps1" -Action check_trust 2>/dev/null | tr -d '\r\n ')
if [ "$ca_trusted" != "yes" ]; then
    echo "[test-local] installing mitmproxy CA ..."
    powershell -NoProfile -ExecutionPolicy Bypass \
        -File "$REPO/shared/_env.ps1" -Action install_trust
fi

# Stop any leftovers from prior runs. Test mode is destructive by design
# (Ctrl+C tears everything down on exit), so we don't bother with the
# "already running" check that run_a/b.sh do — just wipe and start fresh.
_runner_init
_runner_register A     "$PID_A"     "$LOG_A"
_runner_register B     "$PID_B"     "$LOG_B"
_runner_register setup "$PID_SETUP" "$LOG_SETUP"
_runner_kill_all >/dev/null 2>&1 || true
sleep 0.3

echo "[test-local] ★ TEST MODE: 3 workers, foreground only (Ctrl+B disabled)"
echo "[test-local]               setup will run steps 1-8 + OTP-fresh check, NO 登录 click"

# Start B first (listeners), then A (proxy + listener), then setup.
# Modules pick their own LISTEN_PORT defaults (distinct for A vs B) so
# we don't export anything here.
_runner_spawn B     "$PID_B"     "$LOG_B"     "$REPO/server/otp_poller.py"
sleep 0.6
_runner_spawn A     "$PID_A"     "$LOG_A"     "$REPO/local/mitm_capture.py"
sleep 0.4
_runner_spawn setup "$PID_SETUP" "$LOG_SETUP" "$REPO/server/atrust_setup.py" \
    --test --b-host 127.0.0.1 --b-port 7001

_runner_attach --foreground-only
