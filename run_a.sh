#!/usr/bin/env bash
# run_a.sh — Module A (client) one-shot launcher.
#
# Module A runs on the user's WeChat machine. It captures the OAuth
# cookie via mitmproxy and forwards it to Module B on demand. The
# capture flow is reactive: A starts idle (proxy installed, listener
# bound) and only kicks the user via a popup when B signals
# refresh_needed (first OTP request OR cookie failure).
#
# USAGE:
#   bash run_a.sh [--port N] [--peer-port N] [--peer-host H]      # Start
#   bash run_a.sh [--port N] [--peer-port N] [--peer-host H] takeover
#   bash run_a.sh stop                                       # Kill + cleanup
#   bash run_a.sh status                                     # Show state
#
# CONNECTIVITY KNOBS (all optional):
#   --port N        Local listener port (B→A refresh_needed channel)
#   --peer-port N   Remote port to dial (B's listener for A→B cookies)
#   --peer-host H   B's reachable address (IP / domain)
#
# If any knob is omitted, the corresponding env var is used; otherwise the
# Python module's built-in default applies. The numbers themselves are NOT
# baked into this script — operator picks them per deployment.
#
# Env-var fallbacks: LISTEN_HOST / LISTEN_PORT / PEER_HOST / PEER_PORT.
#
# KEYBOARD (foreground only):
#   Ctrl+B   detach: terminate the foreground log, leave client running.
#            Re-attach with `bash run_a.sh takeover`.
#   Ctrl+C   stop everything: kill client, restore HKCU proxy, exit.

set -e
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

source "$REPO/_paths.sh"
ensure_dirs

# ----- parse flags BEFORE sourcing _runner.sh (which sets `set -u`) -------
PORT_ARG=
PEER_PORT_ARG=
PEER_HOST_ARG=
TARGET_HOST_ARG=
POS_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --port)          PORT_ARG="${2:-}";       shift 2 ;;
        --port=*)        PORT_ARG="${1#--port=}"; shift ;;
        --peer-port)     PEER_PORT_ARG="${2:-}";  shift 2 ;;
        --peer-port=*)   PEER_PORT_ARG="${1#--peer-port=}"; shift ;;
        --peer-host)     PEER_HOST_ARG="${2:-}";  shift 2 ;;
        --peer-host=*)   PEER_HOST_ARG="${1#--peer-host=}"; shift ;;
        --target-host)   TARGET_HOST_ARG="${2:-}"; shift 2 ;;
        --target-host=*) TARGET_HOST_ARG="${1#--target-host=}"; shift ;;
        *)               POS_ARGS+=("$1"); shift ;;
    esac
done
for p in "$PORT_ARG" "$PEER_PORT_ARG"; do
    if [ -n "$p" ]; then
        case "$p" in
            *[!0-9]*) echo "[error] port must be an integer, got '$p'" >&2; exit 2 ;;
        esac
    fi
done
if [ ${#POS_ARGS[@]} -gt 0 ]; then
    set -- "${POS_ARGS[@]}"
else
    set --
fi

# Build CLI flag array for the Python worker. Flags-only — no env-var
# passing (the operator passes them on the run_a.sh command line and they
# travel via argv to mitm_capture.py).
WORKER_ARGS=(--listen-host 0.0.0.0)
[ -n "$PORT_ARG" ]        && WORKER_ARGS+=(--listen-port "$PORT_ARG")
[ -n "$PEER_PORT_ARG" ]   && WORKER_ARGS+=(--peer-port  "$PEER_PORT_ARG")
[ -n "$PEER_HOST_ARG" ]   && WORKER_ARGS+=(--peer-host  "$PEER_HOST_ARG")
[ -n "$TARGET_HOST_ARG" ] && WORKER_ARGS+=(--target-host "$TARGET_HOST_ARG")

source "$REPO/shared/_runner.sh"

SUBCMD="${1:-run}"

# ----- subcommand: stop ---------------------------------------------------
if [ "$SUBCMD" = "stop" ] || [ "$SUBCMD" = "kill" ]; then
    _runner_init
    _runner_register A "$PID_A" "$LOG_A"
    _runner_kill_all
    echo "[run_a] stopped."
    exit 0
fi

# ----- subcommand: status -------------------------------------------------
if [ "$SUBCMD" = "status" ]; then
    if [ -f "$PID_A" ]; then
        pid=$(cat "$PID_A")
        if _pid_alive "$pid"; then
            echo "  A running pid=$pid log=$LOG_A"
        else
            echo "  A pidfile exists ($pid) but process is dead"
        fi
    else
        echo "  A not running"
    fi
    exit 0
fi

# ----- pre-flight: python interpreter -------------------------------------
PY=
for _cand in python python3; do
    if command -v "$_cand" >/dev/null 2>&1; then
        if "$_cand" -c 'import sys; print(sys.version_info[0])' 2>/dev/null \
            | grep -q '^3'; then
            PY=$_cand
            break
        fi
    fi
done
[ -n "$PY" ] || { echo "[error] no working python on PATH" >&2; exit 1; }

# ----- pre-flight: python deps + certs ------------------------------------
need_pkgs=()
$PY -c 'import requests'     2>/dev/null || need_pkgs+=("requests")
$PY -c 'import cryptography'  2>/dev/null || need_pkgs+=("cryptography")
$PY -c 'import mitmproxy'    2>/dev/null || need_pkgs+=("mitmproxy")
if [ ${#need_pkgs[@]} -gt 0 ]; then
    echo "[run_a] pip install ${need_pkgs[*]} ..."
    pip install --quiet --disable-pip-version-check "${need_pkgs[@]}"
fi

# A side needs the A<->B cert (link.crt/key) to authenticate to B. The
# B side generates these on first run and the operator copies them to
# the A host. If they're missing here, fail loudly with instructions.
if [ ! -f "$CERT_LINK_CRT" ] || [ ! -f "$CERT_LINK_KEY" ]; then
    cat >&2 <<EOF
[error] A<->B TLS cert missing on this host:
    $CERT_LINK_CRT
    $CERT_LINK_KEY

Generate them on the B host (run_b.sh creates them on first launch),
then copy BOTH files to this machine into:
    $CERTS_DIR

Without the matching cert/key, A cannot authenticate to B.
EOF
    exit 2
fi

# mitmproxy CA install check (silent if already trusted).
ca_trusted=$(powershell -NoProfile -ExecutionPolicy Bypass \
    -File "$REPO/shared/_env.ps1" -Action check_trust 2>/dev/null \
    | tr -d '\r\n ')
if [ "$ca_trusted" != "yes" ]; then
    echo "[run_a] installing mitmproxy CA into HKCU\\Root ..."
    powershell -NoProfile -ExecutionPolicy Bypass \
        -File "$REPO/shared/_env.ps1" -Action install_trust
fi

# ----- subcommand: takeover -----------------------------------------------
if [ "$SUBCMD" = "takeover" ]; then
    _runner_init
    _runner_register A "$PID_A" "$LOG_A"
    _runner_takeover
    exit $?
fi

# ----- subcommand: run (default) ------------------------------------------
# Refuse to start if A is already running (avoid double-spawn).
if [ -f "$PID_A" ]; then
    old_pid=$(cat "$PID_A" 2>/dev/null)
    if [ -n "$old_pid" ] && _pid_alive "$old_pid"; then
        echo "[error] A is already running pid=$old_pid"
        echo "        Use 'bash run_a.sh takeover' to attach,"
        echo "        or 'bash run_a.sh stop' to kill it first."
        exit 1
    fi
    rm -f "$PID_A"  # stale pidfile
fi

_runner_init
_runner_register A "$PID_A" "$LOG_A"
_runner_spawn   A "$PID_A" "$LOG_A" "$REPO/local/mitm_capture.py" "${WORKER_ARGS[@]}"
_runner_attach  --allow-background
