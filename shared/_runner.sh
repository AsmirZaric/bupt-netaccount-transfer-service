#!/usr/bin/env bash
# shared/_runner.sh — helper functions sourced by run_a.sh / run_b.sh /
# run_test_local.sh / run_test_seperate.sh.
#
# Goals:
#   - Detached-spawn long-lived Python workers so they survive the parent
#     bash exit (Ctrl+B "go background" semantics).
#   - Foreground-attach to workers via `tail -f log` PLUS a single-char
#     keyboard reader. Ctrl+B (\x02) cleanly detaches the tail and exits
#     while leaving the workers running. Ctrl+C (SIGINT) tears the whole
#     stack down (workers + tail + PID files + proxy restore via _env.ps1).
#   - Test mode: same foreground attach but Ctrl+B is rejected (test must
#     stay foreground so the operator sees the result).
#
# Functions:
#   _runner_init                    populate WORKERS arrays (call from caller)
#   _runner_register WORKER_NAME PID_FILE LOG_FILE     add a worker to lists
#   _runner_spawn   NAME PIDFILE LOGFILE PY_SCRIPT [ARGS...]
#       Detach-spawn a worker; writes PID to PIDFILE. Echoes the PID.
#   _runner_attach  [--allow-background|--foreground-only]
#       Tail every registered worker's log + listen for keyboard.
#   _runner_kill_all                kill all registered workers, restore proxy.
#
# The caller is expected to:
#   source "$REPO/_paths.sh"  &&  ensure_dirs
#   source "$REPO/shared/_runner.sh"
#   _runner_init
#   _runner_register A "$PID_A" "$LOG_A"            # for each worker
#   _runner_spawn   A "$PID_A" "$LOG_A" \
#       "$REPO/local/mitm_capture.py" --foo --bar
#   _runner_attach   # or --foreground-only

set -u

# ---- registry ------------------------------------------------------------
WORKER_NAMES=()
WORKER_PIDFILES=()
WORKER_LOGFILES=()

_runner_init() {
    WORKER_NAMES=()
    WORKER_PIDFILES=()
    WORKER_LOGFILES=()
}

# ---- platform-aware "is this PID alive?" --------------------------------
# `kill -0 $pid` is unreliable in Git Bash for Windows: the Cygwin/MSYS
# signal layer only tracks Cygwin processes, so it falsely reports native
# Python workers (spawned via DETACHED_PROCESS) as dead. Use tasklist on
# Windows for a Win32-truthful check; fall back to kill -0 on POSIX.
_pid_alive() {
    local pid="$1"
    [ -z "$pid" ] && return 1
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*)
            # tasklist /FI "PID eq X" emits a CSV row iff the PID exists.
            # /NH suppresses the header so we can grep for the PID directly.
            # MSYS_NO_PATHCONV=1 stops MSYS from mangling /FI into a
            # Windows path "C:/Program Files/Git/FI".
            MSYS_NO_PATHCONV=1 tasklist /FI "PID eq $pid" /FO csv /NH \
                2>/dev/null | grep -q "\"$pid\""
            ;;
        *)
            kill -0 "$pid" 2>/dev/null
            ;;
    esac
}

# ---- kill orphan tail+awk pipelines from prior abnormal exits -----------
# When a parent bash exits cleanly via Ctrl+B/Ctrl+C, _runner_stop_tails
# kills its tails. But when the parent is killed externally (closed SSH
# session, force-killed terminal, etc.), the tail.exe + awk.exe pipeline
# survives as an orphan. The next attach starts a NEW tail on the same
# log file, and BOTH tails print every new line → duplicated output.
#
# Strategy: at attach time, kill any tail.exe/awk.exe whose command line
# references our atrust-vpn/logs path or our worker-tag prefixes. Limit
# the match strings tight enough that we don't nuke unrelated tails.
_runner_kill_orphan_tails() {
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*) ;;
        *) return 0 ;;  # POSIX: relying on job control cleanup is fine
    esac
    MSYS_NO_PATHCONV=1 powershell -NoProfile -Command "
        Get-CimInstance Win32_Process |
            Where-Object { (\$_.Name -eq 'tail.exe' -or \$_.Name -eq 'awk.exe') -and
                           \$_.CommandLine -match 'atrust-vpn' } |
            ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }
    " >/dev/null 2>&1 || true
}

_runner_register() {
    WORKER_NAMES+=("$1")
    WORKER_PIDFILES+=("$2")
    WORKER_LOGFILES+=("$3")
}

# ---- detached spawn ------------------------------------------------------
# Args: NAME PIDFILE LOGFILE PY_SCRIPT [extra py args ...]
# Uses shared/_spawn.py to launch the target with Windows DETACHED_PROCESS
# + CREATE_NEW_PROCESS_GROUP. Writes the spawned PID to PIDFILE.
_runner_spawn() {
    local name="$1"; shift
    local pidfile="$1"; shift
    local logfile="$1"; shift
    local script="$1"; shift
    local pid
    # _spawn.py prints the spawned PID on stdout.
    pid=$(python "$REPO/shared/_spawn.py" "$script" "$logfile" "$@") || {
        printf '[runner] spawn %s failed\n' "$name" >&2
        return 1
    }
    printf '%s\n' "$pid" > "$pidfile"
    printf '[runner] spawned %s pid=%s log=%s\n' "$name" "$pid" "$logfile"
}

# ---- kill all registered workers ----------------------------------------
_runner_kill_all() {
    local i name pidfile pid
    for i in "${!WORKER_NAMES[@]}"; do
        name="${WORKER_NAMES[$i]}"
        pidfile="${WORKER_PIDFILES[$i]}"
        if [ -f "$pidfile" ]; then
            pid=$(cat "$pidfile" 2>/dev/null)
            if _pid_alive "$pid"; then
                # taskkill is more reliable than `kill -9` on Windows-native
                # workers; fall back to kill -9 on POSIX.
                case "$(uname -s 2>/dev/null)" in
                    MINGW*|MSYS*|CYGWIN*)
                        MSYS_NO_PATHCONV=1 taskkill /F /PID "$pid" \
                            >/dev/null 2>&1 || true ;;
                    *)
                        kill -9 "$pid" 2>/dev/null || true ;;
                esac
                printf '[runner] killed %s pid=%s\n' "$name" "$pid"
            fi
            rm -f "$pidfile"
        fi
    done
    # Belt-and-braces cleanup: nuke any lingering python.exe matching our
    # script names + tail orphans + restore HKCU proxy.
    powershell -NoProfile -ExecutionPolicy Bypass \
        -File "$REPO/shared/_env.ps1" -Action kill_all >/dev/null 2>&1 || true
}

# ---- foreground attach (tail + keyboard reader) -------------------------
# Optional args:
#   --foreground-only   Ctrl+B is rejected (test mode).
_runner_attach() {
    # Nuke orphan tails from prior abnormal exits BEFORE we start new
    # tails. Otherwise every new line gets printed once per surviving
    # orphan and the operator sees duplicated logs.
    _runner_kill_orphan_tails

    local allow_background=1
    case "${1:-}" in
        --foreground-only) allow_background=0 ;;
        --allow-background) allow_background=1 ;;
    esac

    local TAIL_PIDS=()
    local i logfile
    for i in "${!WORKER_NAMES[@]}"; do
        logfile="${WORKER_LOGFILES[$i]}"
        # Tag each line with the worker name so multi-worker (B + setup)
        # interleaved output stays readable.
        local tag="${WORKER_NAMES[$i]}"
        ( tail -n0 -f "$logfile" 2>/dev/null \
          | awk -v t="[$tag] " '{ print t $0; fflush() }' ) &
        TAIL_PIDS+=($!)
    done

    _runner_stop_tails() {
        local p
        for p in "${TAIL_PIDS[@]}"; do
            kill "$p" 2>/dev/null || true
        done
    }

    # Ctrl+C handler: kill workers + tails + restore proxy + exit.
    _runner_on_int() {
        trap '' INT TERM
        printf '\n[runner] Ctrl+C: cleaning up workers + restoring proxy ...\n'
        _runner_stop_tails
        _runner_kill_all
        exit 0
    }
    trap _runner_on_int INT TERM

    if [ "$allow_background" -eq 1 ]; then
        printf '\n'
        printf '\033[1;36m[runner] %d worker(s) running. Ctrl+B = 后台 / Ctrl+C = 杀全部退出\033[0m\n' \
               "${#WORKER_NAMES[@]}"
    else
        printf '\n'
        printf '\033[1;33m[runner] %d worker(s) running (foreground-only, 不允许后台). Ctrl+C = 杀全部退出\033[0m\n' \
               "${#WORKER_NAMES[@]}"
    fi

    # Reader loop. read -rsn1 returns one raw byte at a time. \x02 = ^B.
    # On Ctrl+C, trap fires + read returns nonzero + we exit via the trap.
    local ch
    while IFS= read -rsn1 ch; do
        case "$ch" in
            $'\x02')  # Ctrl+B
                if [ "$allow_background" -eq 1 ]; then
                    _runner_stop_tails
                    printf '\n\033[1;32m[runner] detached. Worker(s) 继续后台运行:\033[0m\n'
                    local j
                    for j in "${!WORKER_NAMES[@]}"; do
                        local p
                        p=$(cat "${WORKER_PIDFILES[$j]}" 2>/dev/null)
                        printf '  %s  pid=%s  log=%s\n' \
                               "${WORKER_NAMES[$j]}" "$p" "${WORKER_LOGFILES[$j]}"
                    done
                    printf '\033[1;32m  接管: bash $(basename $0) takeover\033[0m\n'
                    trap - INT TERM
                    exit 0
                else
                    printf '\n\033[1;31m[runner] 测试模式禁止后台 (Ctrl+B 已忽略). 使用 Ctrl+C 退出.\033[0m\n'
                fi
                ;;
        esac
    done
    # read returned non-zero (likely SIGINT trap already handled exit).
}

# ---- takeover: verify workers still alive, then attach ------------------
# Caller registers workers first (with their PID files), then calls this.
_runner_takeover() {
    local missing=0 i name pidfile pid
    for i in "${!WORKER_NAMES[@]}"; do
        name="${WORKER_NAMES[$i]}"
        pidfile="${WORKER_PIDFILES[$i]}"
        if [ ! -f "$pidfile" ]; then
            printf '[error] %s: pidfile %s 不存在\n' "$name" "$pidfile" >&2
            missing=1
            continue
        fi
        pid=$(cat "$pidfile" 2>/dev/null)
        if [ -z "$pid" ] || ! _pid_alive "$pid"; then
            printf '[error] %s: pid=%s 已死或不可达\n' "$name" "$pid" >&2
            rm -f "$pidfile"
            missing=1
            continue
        fi
        printf '[runner] takeover %s pid=%s\n' "$name" "$pid"
    done
    if [ "$missing" -eq 1 ]; then
        printf '[error] 没有可接管的后台 worker；用 `bash $(basename $0)` 启动新实例\n' >&2
        return 1
    fi
    _runner_attach --allow-background
}
