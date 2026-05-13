"""Internal: TLS link helpers shared by mitm_capture.py (Module A) and
otp_poller.py (Module B), plus the local B<->setup channel.

Two independent self-signed cert pairs live in DATA_DIR/certs (see
_paths.py — DATA_DIR is %APPDATA%\\atrust-vpn on Windows,
~/.atrust-vpn on POSIX). Crucially these are OUTSIDE the project repo,
so the source tree never contains private keys.

  link.crt / link.key       (CERT_LINK_CRT / CERT_LINK_KEY)
    Used for A<->B over the network (A on user's WeChat machine, B on the
    aTrust server). Both halves of this pair MUST be copied to the A side
    before A is started.

  local.crt / local.key     (CERT_LOCAL_CRT / CERT_LOCAL_KEY)
    Used for B<->setup ON THE SAME MACHINE ONLY. B's setup-channel listener
    is bound strictly to 127.0.0.1; setup is the only legitimate client.
    These files MUST NEVER leave the B+setup host.

Wire format (both pairs): `<4-byte big-endian length><utf-8 JSON>` per message.

Public API:
  ensure_cert()              -> (link.crt path, link.key path)
  ensure_local_cert()        -> (local.crt path, local.key path)
  send(host, port, obj, ...) -> one-shot TLS conn, send 1 msg, close (A<->B)
  serve(port, on_message)    -> blocking parallel TLS listener (A<->B)
  request(host, port, obj)   -> short-lived TLS conn, send 1 + recv 1 reply
                                (B<->setup; uses local cert by default)
  serve_local(port, on_request)
                             -> blocking SERIAL TLS listener (B<->setup);
                                bind 127.0.0.1 only, 1 connection at a time
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone

import _paths

MAX_MSG_BYTES = 1 << 20  # 1 MB

log = logging.getLogger('link')


def _gen_cert_pair(common_name: str = 'vpn-link') -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem). Self-signed, valid 10 years, SAN includes
    localhost + 127.0.0.1."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _ensure_pair(cert_path: str, key_path: str,
                 cn: str, prefix: str,
                 wait_timeout: float = 10.0) -> tuple[str, str]:
    """Generate (cert,key) atomically into `cert_path`,`key_path` if missing.
    Creates parent dirs as needed (DATA_DIR/certs)."""
    _paths.ensure_dirs()
    parent = os.path.dirname(cert_path)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    if not (os.path.exists(cert_path) or os.path.exists(key_path)):
        cert_pem, key_pem = _gen_cert_pair(common_name=cn)
        fd_c, tmp_c = tempfile.mkstemp(prefix=prefix + '.crt.', dir=parent)
        os.write(fd_c, cert_pem); os.close(fd_c)
        fd_k, tmp_k = tempfile.mkstemp(prefix=prefix + '.key.', dir=parent)
        os.write(fd_k, key_pem); os.close(fd_k)
        try:
            os.replace(tmp_c, cert_path)
        except OSError:
            os.unlink(tmp_c)
        try:
            os.replace(tmp_k, key_path)
        except OSError:
            os.unlink(tmp_k)

    deadline = time.monotonic() + wait_timeout
    while time.monotonic() < deadline:
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
        time.sleep(0.2)
    raise FileNotFoundError(
        f'TLS cert files not available: {cert_path}, {key_path}'
    )


def ensure_cert(wait_timeout: float = 10.0) -> tuple[str, str]:
    """Ensure link.crt + link.key (A<->B) exist under DATA_DIR/certs."""
    return _ensure_pair(_paths.CERT_LINK_CRT, _paths.CERT_LINK_KEY,
                        cn='vpn-link', prefix='link',
                        wait_timeout=wait_timeout)


def ensure_local_cert(wait_timeout: float = 10.0) -> tuple[str, str]:
    """Ensure local.crt + local.key (B<->setup, server-only) exist.

    NEVER copy these files off the B+setup host. They authenticate the local
    OTP channel. If either leaks, regenerate by deleting both and restarting
    B (run_b.sh will regenerate on next start).
    """
    return _ensure_pair(_paths.CERT_LOCAL_CRT, _paths.CERT_LOCAL_KEY,
                        cn='vpn-local', prefix='local',
                        wait_timeout=wait_timeout)


def _make_server_ctx(cert_path: str | None = None,
                     key_path: str | None = None) -> ssl.SSLContext:
    if cert_path is None or key_path is None:
        cert_path, key_path = ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


def _make_client_ctx(cert_path: str | None = None) -> ssl.SSLContext:
    if cert_path is None:
        cert_path, _ = ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=cert_path)
    # The cert isn't issued for the local hostname; we authenticate it by
    # trust-on-shared-key (peer must have the same private key).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _send_msg(sock: ssl.SSLSocket, obj) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    if len(data) > MAX_MSG_BYTES:
        raise ValueError(f'message too large: {len(data)} > {MAX_MSG_BYTES}')
    sock.sendall(struct.pack('>I', len(data)) + data)


def _recv_msg(sock: ssl.SSLSocket):
    hdr = b''
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    n = struct.unpack('>I', hdr)[0]
    if n > MAX_MSG_BYTES:
        raise ValueError(f'message too large: {n} > {MAX_MSG_BYTES}')
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            return None
        buf += chunk
    return json.loads(buf.decode('utf-8'))


def send(host: str, port: int, obj, timeout: float = 5.0) -> None:
    """Open a one-shot TLS connection, send a single JSON message, close.
    Raises on connection / TLS / send errors."""
    ctx = _make_client_ctx()
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        # SNI = actual peer host. A hardcoded "localhost" SNI gets dropped
        # by China-region cloud GFW/middleboxes that flag suspicious SNI
        # values on outbound TLS. check_hostname=False on the ctx, so
        # server_hostname is just an SNI label -- no cert SAN match needed.
        tls = ctx.wrap_socket(raw, server_hostname=host)
        try:
            _send_msg(tls, obj)
        finally:
            try:
                tls.unwrap()
            except OSError:
                pass
            tls.close()
    finally:
        try:
            raw.close()
        except OSError:
            pass


def serve(port: int, on_message, host: str = '127.0.0.1') -> None:
    """Blocking TLS server. Call `on_message(obj)` per received message.
    Each connection is short-lived (one message → close)."""
    ctx = _make_server_ctx()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    log.info('TLS link listening on %s:%d', host, port)
    while True:
        try:
            raw, addr = s.accept()
        except OSError:
            break

        def _handle(conn=raw):
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                try:
                    msg = _recv_msg(tls)
                    if msg is not None:
                        try:
                            on_message(msg)
                        except Exception as e:
                            log.exception('on_message handler crashed: %s', e)
                finally:
                    try:
                        tls.unwrap()
                    except OSError:
                        pass
                    tls.close()
            except Exception as e:
                log.warning('TLS conn error: %s', e)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=_handle, daemon=True).start()


def request(host: str, port: int, obj, timeout: float = 5.0,
            cert_path: str | None = None):
    """Open a short-lived TLS connection, send one message, receive one
    reply, close. Returns the reply dict (or None on graceful close without
    reply). Raises on connection / TLS / send errors.

    Defaults to `_local.crt` so the same call signature works for the
    B<->setup channel without the caller having to pass cert paths.
    """
    if cert_path is None:
        cert_path, _ = ensure_local_cert()
    ctx = _make_client_ctx(cert_path=cert_path)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        # Match `send()` -- SNI = actual host. Even for the loopback setup
        # channel this is harmless (check_hostname=False).
        tls = ctx.wrap_socket(raw, server_hostname=host)
        try:
            _send_msg(tls, obj)
            return _recv_msg(tls)
        finally:
            try:
                tls.unwrap()
            except OSError:
                pass
            tls.close()
    finally:
        try:
            raw.close()
        except OSError:
            pass


def serve_local(port: int, on_request,
                host: str = '127.0.0.1',
                cert_path: str | None = None,
                key_path: str | None = None) -> None:
    """Blocking SERIAL TLS server for the B<->setup channel.

      - Strict loopback bind. `host` defaults to '127.0.0.1' and the caller
        SHOULD NOT pass anything else: an external bind defeats the security
        model of this channel.
      - `on_request(msg) -> reply_obj`. The reply is sent back on the SAME
        connection, then the connection is closed.
      - Serial accept loop: the next connection is only accepted after the
        current one is fully drained and closed. Enforces the
        "exactly one setup subscriber" invariant naturally — no concurrent
        clients can coexist.

    Defaults to `_local.crt` / `_local.key` if cert paths aren't passed.
    """
    if host != '127.0.0.1':
        log.warning('serve_local invoked with host=%r — security model '
                    'assumes loopback bind only', host)
    if cert_path is None or key_path is None:
        cert_path, key_path = ensure_local_cert()
    ctx = _make_server_ctx(cert_path=cert_path, key_path=key_path)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    # Backlog 1: discourage queued parallel clients. The serial accept loop
    # is the authoritative single-subscriber enforcement.
    s.listen(1)
    log.info('TLS req-reply (single-subscriber) listening on %s:%d',
             host, port)
    while True:
        try:
            raw, addr = s.accept()
        except OSError:
            break
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
            try:
                msg = _recv_msg(tls)
                if msg is not None:
                    try:
                        reply = on_request(msg)
                    except Exception as e:
                        log.exception('on_request handler crashed: %s', e)
                        reply = {'type': 'error', 'message': str(e)}
                    if reply is not None:
                        try:
                            _send_msg(tls, reply)
                        except Exception as e:
                            log.warning('reply send failed: %s', e)
            finally:
                try:
                    tls.unwrap()
                except OSError:
                    pass
                tls.close()
        except Exception as e:
            log.warning('TLS conn error: %s', e)
        finally:
            try:
                raw.close()
            except OSError:
                pass
