"""gateway/tcp_forward.py — generic static TCP port forwarder.

Listens on `--listen-port` and bidirectionally splices each connection
to a fixed `--target host:port`. The target is reached through whatever
routing the host already has (this is what makes the forwarder useful
when the gateway machine sits inside a private network the local
machine cannot reach directly).

This is a pure byte forwarder — no TLS termination, no protocol
awareness. Designed for protocols where the server initiates with a
banner (SSH, FTP control, MySQL, ...) — aTrust-style VPN clients that
hook TLS at the per-process layer don't inspect plain TCP, so this
works for SSH where direct TLS proxying would not.

Example (expose a private SSH host through a public-facing gateway):

    # On the gateway machine, inside the VPN context:
    python tcp_forward.py --listen-port <N> --target <private-host>:22

    # From any client that can reach the gateway:
    ssh -p <N> user@<gateway-host>      # == ssh user@<private-host>

Usage:
    python tcp_forward.py --listen-port N --target HOST:PORT
                          [--host 0.0.0.0]
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import sys
import threading
import time

BUFSIZE = 65536
DIAL_TIMEOUT_S = 15

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d [tcp-fwd %(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S',
)
log = logging.getLogger('tcp-fwd')

_shutdown = threading.Event()


def _splice(a: socket.socket, b: socket.socket, tag: str) -> None:
    counters = {'c->u': 0, 'u->c': 0}
    start = time.monotonic()

    def fwd(src: socket.socket, dst: socket.socket, label: str) -> None:
        n = 0
        try:
            while not _shutdown.is_set():
                try:
                    data = src.recv(BUFSIZE)
                except OSError:
                    return
                if not data:
                    break
                try:
                    dst.sendall(data)
                except OSError:
                    return
                n += len(data)
        finally:
            counters[label] += n
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=fwd, args=(a, b, 'c->u'), daemon=True)
    t2 = threading.Thread(target=fwd, args=(b, a, 'u->c'), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    log.info('%s  closed  c->u=%d  u->c=%d  (%.2fs)',
             tag, counters['c->u'], counters['u->c'],
             time.monotonic() - start)


def _handle(client: socket.socket, addr: tuple,
            target_host: str, target_port: int) -> None:
    src = f'{addr[0]}:{addr[1]}'
    dst = f'{target_host}:{target_port}'
    tag = f'{src}<->{dst}'
    upstream: socket.socket | None = None
    try:
        try:
            upstream = socket.create_connection(
                (target_host, target_port), timeout=DIAL_TIMEOUT_S)
            upstream.settimeout(None)
        except Exception as e:
            log.warning('%s  dial %s failed: %s: %s',
                        src, dst, type(e).__name__, e)
            return
        log.info('%s  open', tag)
        _splice(client, upstream, tag=tag)
    except Exception as e:
        log.warning('%s  handler crashed: %s', src, e)
    finally:
        try:
            client.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='static TCP port forwarder')
    p.add_argument('--listen-port', type=int, required=True,
                   help='local port to listen on')
    p.add_argument('--target', required=True,
                   help='upstream "host:port" to forward to')
    p.add_argument('--host', default='0.0.0.0',
                   help='listen interface (default 0.0.0.0)')
    return p.parse_args(argv)


def main() -> int:
    args = _parse_args()
    if ':' not in args.target:
        print(f'--target must be "host:port", got {args.target!r}',
              file=sys.stderr)
        return 2
    target_host, _, port_s = args.target.rpartition(':')
    target_host = target_host.strip('[]')
    try:
        target_port = int(port_s)
    except ValueError:
        print(f'--target port not an integer: {port_s!r}', file=sys.stderr)
        return 2

    def on_sig(*_):
        log.info('signal received, exiting')
        _shutdown.set()
        sys.exit(130)
    signal.signal(signal.SIGINT, on_sig)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, on_sig)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.listen_port))
    srv.listen(64)
    log.info('=' * 60)
    log.info('  TCP forward  %s:%d  ->  %s:%d',
             args.host, args.listen_port, target_host, target_port)
    log.info('=' * 60)

    while not _shutdown.is_set():
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        threading.Thread(
            target=_handle,
            args=(conn, addr, target_host, target_port),
            daemon=True,
        ).start()
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
