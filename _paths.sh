#!/usr/bin/env bash
# _paths.sh — bash equivalent of shared/_paths.py
#
# Sourced by every run_*.sh so the bash and Python sides agree on where
# secrets / logs / PIDs live. Override the base via ATRUST_VPN_DATA env.
#
# Usage:
#     source "$(dirname "${BASH_SOURCE[0]}")/_paths.sh"
#     echo "$LOG_A"     # -> $DATA_DIR/logs/a.log

# ----- resolve DATA_DIR (must match shared/_paths.py exactly) -------------
if [ -n "$ATRUST_VPN_DATA" ]; then
    DATA_DIR="$ATRUST_VPN_DATA"
elif [ -n "$APPDATA" ]; then
    # Windows: %APPDATA%\atrust-vpn  ->  $APPDATA/atrust-vpn (bash-friendly)
    DATA_DIR="$APPDATA/atrust-vpn"
else
    DATA_DIR="$HOME/.atrust-vpn"
fi

CERTS_DIR="$DATA_DIR/certs"
LOGS_DIR="$DATA_DIR/logs"
STATE_DIR="$DATA_DIR/state"

# ----- TLS certs (generated lazily by _link.ensure_cert) -------------------
CERT_LINK_CRT="$CERTS_DIR/link.crt"
CERT_LINK_KEY="$CERTS_DIR/link.key"
CERT_LOCAL_CRT="$CERTS_DIR/local.crt"
CERT_LOCAL_KEY="$CERTS_DIR/local.key"

# ----- Logs --------------------------------------------------------------
LOG_A="$LOGS_DIR/a.log"
LOG_B="$LOGS_DIR/b.log"
LOG_SETUP="$LOGS_DIR/setup.log"
LOG_MITM="$LOGS_DIR/mitm.log"
LOG_RECORD="$LOGS_DIR/record.log"

# ----- State --------------------------------------------------------------
PID_A="$STATE_DIR/a.pid"
PID_B="$STATE_DIR/b.pid"
PID_SETUP="$STATE_DIR/setup.pid"
CAPTURE_FLAG="$STATE_DIR/capture.flag"
PROXY_BACKUP="$STATE_DIR/proxy_backup.json"

ensure_dirs() {
    mkdir -p "$DATA_DIR" "$CERTS_DIR" "$LOGS_DIR" "$STATE_DIR"
}
