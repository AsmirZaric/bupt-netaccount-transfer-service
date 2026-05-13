"""Detach a Python script as a fully independent Windows process.

Used by run.sh `service` mode. Equivalent of POSIX double-fork: the child is
detached from the calling shell's process group and console, so Ctrl+C in the
shell cannot terminate it.

Usage:
    python _spawn.py <target.py> <stdout_log_path> [extra args...]

The first two positional args are fixed; any trailing args become argv[1:]
to the spawned target script. Prints the spawned PID on stdout.
"""

from __future__ import annotations

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Windows process creation flags
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
# Break free of any inherited Job Object. Critical when the caller is
# itself inside a Job (Windows OpenSSH wraps every SSH session in a
# Job Object; the parent's exit normally tears down every process in
# the Job — including ones we want to keep running). Harmless when
# not in a Job. Without this, run_b.sh via SSH spawns workers that die
# when the SSH channel closes.
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def main() -> int:
    if len(sys.argv) < 3:
        print(f'usage: {sys.argv[0]} <target.py> <stdout_log_path> [extra...]',
              file=sys.stderr)
        return 2
    target = sys.argv[1]
    log_path = sys.argv[2]
    extra_args = sys.argv[3:]
    if not os.path.isabs(target):
        target = os.path.join(HERE, target)
    if not os.path.isabs(log_path):
        log_path = os.path.join(HERE, log_path)

    log_fh = open(log_path, 'w', encoding='utf-8', errors='replace', buffering=1)
    flags = (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
             | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB)
    # Force the child's sys.stdout/sys.stderr to UTF-8. Otherwise Python on
    # Chinese Windows writes CP936/GBK bytes into the log file, and the bash
    # tail pipeline on the operator side (typically UTF-8) renders them as
    # mojibake (e.g. "无法连接" -> "□޷□□□□ӵ□").
    child_env = os.environ.copy()
    child_env['PYTHONIOENCODING'] = 'utf-8'
    child_env['PYTHONUTF8'] = '1'
    try:
        proc = subprocess.Popen(
            [sys.executable, target] + list(extra_args),
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=HERE,
            creationflags=flags,
            close_fds=True,
            env=child_env,
        )
    except OSError as e:
        # CREATE_BREAKAWAY_FROM_JOB requires the parent's Job to permit
        # breakaway (JOB_OBJECT_LIMIT_BREAKAWAY_OK). If it's denied,
        # retry without that flag — the parent's Job will then propagate
        # its lifecycle, but at least we don't crash here.
        if 'Access is denied' in str(e) or getattr(e, 'winerror', 0) == 5:
            proc = subprocess.Popen(
                [sys.executable, target] + list(extra_args),
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                cwd=HERE,
                creationflags=(flags & ~CREATE_BREAKAWAY_FROM_JOB),
                close_fds=True,
                env=child_env,
            )
        else:
            raise
    # We don't keep `proc` around; the OS now owns it.
    print(proc.pid)
    return 0


if __name__ == '__main__':
    sys.exit(main())
