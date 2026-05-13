#!/usr/bin/env bash
# run_b.sh — Module B (server) one-shot launcher.
#
# B host runs TWO long-lived workers:
#   1. otp_poller.py     - listens 0.0.0.0:<--port> (A->B cookies) +
#                          127.0.0.1:7001 (setup channel); polls /otp.
#   2. atrust_setup.py   - drives the aTrust UI, then enters the
#                          keepalive loop (Phase 0 probe → setup or
#                          continued probing → reconnect on disconnect).
#
# USAGE:
#   bash run_b.sh [--port N] [--peer-port N] [--peer-host H]      # Start
#   bash run_b.sh [--port N] [--peer-port N] [--peer-host H] takeover
#   bash run_b.sh stop                                       # Kill + cleanup
#   bash run_b.sh status                                     # Show state
#
# CONNECTIVITY KNOBS (all optional):
#   --port N        Local listener port (A→B cookie channel)
#   --peer-port N   Remote port to dial (A's listener for refresh_needed)
#   --peer-host H   A's reachable address (IP / domain)
#
# If any knob is omitted, the corresponding env var is used; otherwise the
# Python module's built-in default applies. The numbers themselves are NOT
# baked into this script — operator picks them per deployment.
#
# Env-var fallbacks: LISTEN_HOST / LISTEN_PORT / PEER_HOST / PEER_PORT.
#
# KEYBOARD (foreground only):
#   Ctrl+B   detach: leave both workers running, exit foreground.
#            Re-attach with `bash run_b.sh takeover`.
#   Ctrl+C   stop everything: kill workers, exit.
#
# On first launch B generates BOTH cert pairs:
#   link.crt + link.key   (A<->B) -- copy to the A host's DATA_DIR/certs
#   local.crt + local.key (B<->setup) -- stays on this host

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
VPN_URL_ARG=
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
        --vpn-url)       VPN_URL_ARG="${2:-}"; shift 2 ;;
        --vpn-url=*)     VPN_URL_ARG="${1#--vpn-url=}"; shift ;;
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

# Build CLI flag array for B (otp_poller.py). Flags-only — no env-var
# passing; values travel via argv to the Python child.
WORKER_ARGS=(--listen-host 0.0.0.0)
[ -n "$PORT_ARG" ]        && WORKER_ARGS+=(--listen-port "$PORT_ARG")
[ -n "$PEER_PORT_ARG" ]   && WORKER_ARGS+=(--peer-port  "$PEER_PORT_ARG")
[ -n "$PEER_HOST_ARG" ]   && WORKER_ARGS+=(--peer-host  "$PEER_HOST_ARG")
[ -n "$TARGET_HOST_ARG" ] && WORKER_ARGS+=(--target-host "$TARGET_HOST_ARG")

SETUP_ARGS=(--b-host 127.0.0.1 --b-port 7001)
[ -n "$VPN_URL_ARG" ] && SETUP_ARGS+=(--url "$VPN_URL_ARG")

source "$REPO/shared/_runner.sh"

SUBCMD="${1:-run}"

register_workers() {
    _runner_init
    _runner_register B     "$PID_B"     "$LOG_B"
    _runner_register setup "$PID_SETUP" "$LOG_SETUP"
}

# ----- subcommand: stop ---------------------------------------------------
if [ "$SUBCMD" = "stop" ] || [ "$SUBCMD" = "kill" ]; then
    register_workers
    _runner_kill_all
    echo "[run_b] stopped."
    exit 0
fi

# ----- subcommand: status -------------------------------------------------
if [ "$SUBCMD" = "status" ]; then
    for kv in "B:$PID_B:$LOG_B" "setup:$PID_SETUP:$LOG_SETUP"; do
        IFS=: read -r name pidfile logfile <<< "$kv"
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile")
            if _pid_alive "$pid"; then
                echo "  $name running pid=$pid log=$logfile"
            else
                echo "  $name pidfile exists ($pid) but process is dead"
            fi
        else
            echo "  $name not running"
        fi
    done
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

# ----- pre-flight: deps + certs (generated on first launch) ---------------
need_pkgs=()
$PY -c 'import requests'     2>/dev/null || need_pkgs+=("requests")
$PY -c 'import cryptography'  2>/dev/null || need_pkgs+=("cryptography")
$PY -c 'import pywinauto'    2>/dev/null || need_pkgs+=("pywinauto")
$PY -c 'import psutil'       2>/dev/null || need_pkgs+=("psutil")
if [ ${#need_pkgs[@]} -gt 0 ]; then
    echo "[run_b] pip install ${need_pkgs[*]} ..."
    pip install --quiet --disable-pip-version-check "${need_pkgs[@]}"
fi

NEW_LINK_CERT=no
if [ ! -f "$CERT_LINK_CRT" ] || [ ! -f "$CERT_LINK_KEY" ]; then
    echo "[run_b] generating A<->B cert pair (link.crt/link.key, one-time)..."
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_cert()'
    NEW_LINK_CERT=yes
fi
if [ ! -f "$CERT_LOCAL_CRT" ] || [ ! -f "$CERT_LOCAL_KEY" ]; then
    echo "[run_b] generating B<->setup cert pair (local.crt/local.key, one-time)..."
    PYTHONPATH="$REPO/shared" $PY -c 'import _link; _link.ensure_local_cert()'
fi
if [ "$NEW_LINK_CERT" = "yes" ]; then
    cat <<EOF

============================================================
  IMPORTANT: copy the A<->B cert pair to the A-side machine:

      $CERT_LINK_CRT
      $CERT_LINK_KEY

  Destination on A host: \$CERTS_DIR (= same path layout under
  %APPDATA%\\atrust-vpn\\certs by default). Then run run_a.sh on A.

  ⚠  Do NOT copy $CERTS_DIR/local.* anywhere — those secure the
     loopback B<->setup channel and must stay on THIS host.
============================================================

EOF
fi

# aTrust install check
ATRUST_EXE="C:/Program Files (x86)/Sangfor/aTrust/aTrustTray/aTrustTray.exe"
[ -f "$ATRUST_EXE" ] || { echo "[error] aTrust not installed at $ATRUST_EXE" >&2; exit 2; }

# ----- subcommand: takeover -----------------------------------------------
if [ "$SUBCMD" = "takeover" ]; then
    register_workers
    _runner_takeover
    exit $?
fi

# ----- subcommand: run (default) ------------------------------------------
for kv in "B:$PID_B" "setup:$PID_SETUP"; do
    IFS=: read -r name pidfile <<< "$kv"
    if [ -f "$pidfile" ]; then
        old_pid=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$old_pid" ] && _pid_alive "$old_pid"; then
            echo "[error] $name already running pid=$old_pid"
            echo "        bash run_b.sh takeover  /  bash run_b.sh stop"
            exit 1
        fi
        rm -f "$pidfile"
    fi
done

register_workers
# Start B first so its listeners are up before setup connects.
_runner_spawn B "$PID_B" "$LOG_B" "$REPO/server/otp_poller.py" "${WORKER_ARGS[@]}"
# Give B a moment to bind sockets.
sleep 0.6
_runner_spawn setup "$PID_SETUP" "$LOG_SETUP" "$REPO/server/atrust_setup.py" \
    "${SETUP_ARGS[@]}"
_runner_attach --allow-background
