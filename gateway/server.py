"""gateway/server.py — URL-forwarding API.

Listens on port 80 (HTTP) and 443 (HTTPS, self-signed). Each request URL
must carry a `?url=<target>` query parameter; the gateway fetches that
target server-side and streams the response back verbatim — status code,
headers, and body — so the client sees exactly what the upstream sent.

Examples (browser, curl, anything that speaks HTTP/HTTPS):

    https://<gateway-host>/?url=https://example.com/
    http://<gateway-host>/?url=https://example.com/
    curl -k 'https://<gateway-host>/?url=https://example.com/'

Browser will warn about the self-signed cert; click through.

The URL on the right side of `?url=` should be URL-encoded if it
contains its own '?', '&', or '#':

    /?url=https%3A%2F%2Fexample.com%2Flogin%3Fnext%3D%2Fdash

Usage:
    python server.py [--http-port 80] [--https-port 443]
                     [--public-host HOST_OR_IP]
                     [--cert PATH] [--key PATH]
"""

from __future__ import annotations

import argparse
import http.server
import ipaddress
import logging
import os
import signal
import socket
import socketserver
import ssl
import sys
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone

import requests
import urllib3

# Upstream certs are usually re-signed by aTrust's SSL hook; trust whatever
# the OS returns. Silence the urllib3 InsecureRequestWarning spam.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Resolve shared/ for _paths
_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared')
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)
import _paths  # noqa: E402

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
TIMEOUT_S = 30
BUFSIZE = 8192

# Set from --public-host arg in main(); used as a fallback when the request
# omits the Host header (most well-behaved clients send it).
_PUBLIC_HOST: str = ''


def _detect_public_host() -> str:
    """Best-effort hostname for the self-signed cert SAN. Falls back to the
    machine's primary IPv4. If neither works, use 'localhost'."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return 'localhost'

# RFC 7230 hop-by-hop headers — must not be forwarded.
HOP_BY_HOP = frozenset({
    'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailer',
    'transfer-encoding', 'upgrade',
})

# Cookie used to remember the current upstream scheme+host across requests.
# Set whenever an explicit ?url= comes in OR a Location header is rewritten.
# Read when neither ?url= nor a Referer-with-?url= is available — typically
# fonts/images referenced from a CSS file (where Referer is the CSS URL,
# which has no ?url= of its own).
ORIGIN_COOKIE = '__gw_origin'


def _strip_cookie_domain(value: str) -> str:
    """Remove `Domain=...` attribute from a Set-Cookie header value, so the
    cookie binds to the gateway's host rather than the upstream's domain."""
    import re as _re
    return _re.sub(r';\s*Domain\s*=\s*[^;]+', '', value, flags=_re.IGNORECASE)


def _rewrite_location(loc: str, gateway_origin: str,
                      upstream_origin: str) -> str:
    """Rewrite an absolute upstream Location into a gateway URL so the
    browser stays inside the gateway when following 3xx redirects.

      same upstream  ->  swap host portion (relative-equivalent)
      cross upstream ->  wrap in /?url=<encoded>
      gateway / relative / weird  ->  unchanged
    """
    if not loc:
        return loc
    s = loc.lstrip().lower()
    if not (s.startswith('http://') or s.startswith('https://')):
        return loc  # relative path or scheme-less; leave for browser to resolve
    if loc.startswith(gateway_origin):
        return loc
    if upstream_origin and (
            loc == upstream_origin or loc.startswith(upstream_origin + '/')):
        return gateway_origin + loc[len(upstream_origin):]
    return f'{gateway_origin}/?url={urllib.parse.quote(loc, safe="")}'

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d [gateway %(levelname)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S',
)
log = logging.getLogger('gateway')


# ---------------------------------------------------------------------------
# Self-signed cert for the HTTPS listener
# ---------------------------------------------------------------------------

def _ensure_self_signed_cert(public_ip: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    _paths.ensure_dirs()
    crt = os.path.join(_paths.CERTS_DIR, 'gateway.crt')
    key = os.path.join(_paths.CERTS_DIR, 'gateway.key')
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key

    log.info('generating self-signed gateway cert at %s', crt)
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, public_ip)])
    san = [x509.DNSName('localhost'),
           x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))]
    try:
        san.append(x509.IPAddress(ipaddress.IPv4Address(public_ip)))
    except ValueError:
        san.append(x509.DNSName(public_ip))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pkey.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .sign(pkey, hashes.SHA256())
    )
    with open(crt, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key, 'wb') as f:
        f.write(pkey.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return crt, key


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class GatewayHandler(http.server.BaseHTTPRequestHandler):
    # Quiet the per-request access log noise; we already log selectively.
    def log_message(self, *_):
        pass

    def _send_text(self, code: int, msg: str) -> None:
        body = msg.encode('utf-8')
        try:
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def _read_origin_cookie(self) -> str:
        """Parse the __gw_origin cookie value (URL-encoded scheme://host)."""
        for piece in self.headers.get('Cookie', '').split(';'):
            piece = piece.strip()
            if '=' not in piece:
                continue
            k, _, v = piece.partition('=')
            if k.strip() == ORIGIN_COOKIE:
                return urllib.parse.unquote(v.strip())
        return ''

    def _gateway_origin(self) -> str:
        """e.g. 'https://<gateway-host>' — derived from the listener kind +
        Host header. Used for cookie scoping + Location rewriting."""
        host = self.headers.get('Host') or _PUBLIC_HOST or '127.0.0.1'
        scheme = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
        return f'{scheme}://{host}'

    def _resolve_target(self):
        """Three-tier resolution for the upstream URL of this request:

          1. Explicit ?url=<target> on this request.
          2. Referer carries ?url=<base>  (a sub-resource fetched from a
             page that was loaded via the gateway).
          3. __gw_origin cookie  — set by the gateway on a previous
             response; covers fonts/images referenced from a CSS file
             whose Referer no longer carries ?url=.

        Returns (target_url, source_tag, origin) or (None, error_msg, None).
        `origin` is scheme://host of the upstream, used to set the cookie
        and to rewrite Location headers.
        """
        parsed = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if 'url' in qs and qs['url'][0]:
            target = qs['url'][0]
            tp = urllib.parse.urlsplit(target)
            if tp.scheme in ('http', 'https') and tp.netloc:
                return target, 'query', f'{tp.scheme}://{tp.netloc}'
            return None, f'bad url scheme: {target!r}\n', None

        ref = self.headers.get('Referer', '')
        if ref:
            ref_parsed = urllib.parse.urlsplit(ref)
            ref_qs = urllib.parse.parse_qs(
                ref_parsed.query, keep_blank_values=True)
            if 'url' in ref_qs and ref_qs['url'][0]:
                base = urllib.parse.urlsplit(ref_qs['url'][0])
                if base.scheme in ('http', 'https') and base.netloc:
                    rebuilt = urllib.parse.urlunsplit((
                        base.scheme, base.netloc,
                        parsed.path or '/', parsed.query, ''))
                    return rebuilt, 'referer', f'{base.scheme}://{base.netloc}'

        cookie_origin = self._read_origin_cookie()
        if cookie_origin:
            cp = urllib.parse.urlsplit(cookie_origin)
            if cp.scheme in ('http', 'https') and cp.netloc:
                rebuilt = urllib.parse.urlunsplit((
                    cp.scheme, cp.netloc,
                    parsed.path or '/', parsed.query, ''))
                return rebuilt, 'cookie', f'{cp.scheme}://{cp.netloc}'

        return None, ('Missing ?url= query parameter, and no Referer or '
                      'gateway-origin cookie to fall back on.\n\n'
                      'Example: GET /?url=https://example.com/\n'), None

    def _forward(self) -> None:
        target, src, upstream_origin = self._resolve_target()
        if target is None:
            return self._send_text(400, src)
        # Sanity: target must have scheme
        tparsed = urllib.parse.urlsplit(target)
        if tparsed.scheme not in ('http', 'https'):
            return self._send_text(
                400, f'url scheme must be http or https, got {tparsed.scheme!r}\n')
        gateway_origin = self._gateway_origin()

        # Body (if any)
        body = None
        cl = self.headers.get('Content-Length')
        if cl is not None:
            try:
                n = int(cl)
            except ValueError:
                return self._send_text(400, 'invalid Content-Length\n')
            if n > 0:
                body = self.rfile.read(n)

        # Forwarded request headers (strip Host + hop-by-hop)
        fwd_headers = {}
        for name, val in self.headers.items():
            if name.lower() in HOP_BY_HOP:
                continue
            if name.lower() == 'host':
                continue
            fwd_headers[name] = val
        # Honour Host of the target
        fwd_headers['Host'] = tparsed.netloc

        client = self.client_address[0] if self.client_address else '?'
        log.info('%s  %s %s', client, self.command, target)
        try:
            r = requests.request(
                self.command, target,
                headers=fwd_headers, data=body,
                allow_redirects=False, stream=True,
                timeout=TIMEOUT_S, verify=False,
            )
        except requests.RequestException as e:
            log.warning('%s  upstream error: %s', client, e)
            return self._send_text(502, f'upstream error: {e}\n')

        # Relay status + headers (excluding hop-by-hop + length/encoding,
        # which we re-derive when streaming).
        try:
            self.send_response(r.status_code, r.reason or '')
        except OSError:
            r.close()
            return
        body_iter = r.iter_content(BUFSIZE)
        # Buffer the body so we can send accurate Content-Length;
        # streaming with chunked encoding via http.server is brittle.
        chunks = []
        total = 0
        for chunk in body_iter:
            chunks.append(chunk)
            total += len(chunk)
        r.close()

        for name, val in r.headers.items():
            if name.lower() in HOP_BY_HOP:
                continue
            if name.lower() in ('content-length', 'content-encoding'):
                # If upstream sent gzip etc., requests already decoded the
                # bytes we have; the stored length / encoding no longer match.
                continue
            if name.lower() == 'set-cookie':
                # Strip Domain=upstream.tld so the cookie binds to the
                # gateway's host — otherwise the browser stores it under
                # the real upstream domain and never echoes it back to us.
                val = _strip_cookie_domain(val)
            if name.lower() == 'location':
                val = _rewrite_location(val, gateway_origin, upstream_origin)
            self.send_header(name, val)
        # If requests merged multiple Set-Cookie headers into r.headers
        # they show up only once. Walk raw headers to be safe.
        try:
            raw_set_cookies = r.raw.headers.getlist('Set-Cookie')  # type: ignore[attr-defined]
        except Exception:
            raw_set_cookies = []
        if len(raw_set_cookies) > 1:
            # Re-send the de-duplicated set so each value is its own header
            # (BaseHTTPRequestHandler already wrote one above; skip index 0).
            for sc in raw_set_cookies[1:]:
                self.send_header('Set-Cookie', _strip_cookie_domain(sc))
        # Tell the browser the current upstream for follow-up sub-resource
        # requests (CSS-referenced fonts/images, where Referer is the CSS
        # URL — already on the gateway but without a ?url= query).
        if upstream_origin:
            self.send_header(
                'Set-Cookie',
                f'{ORIGIN_COOKIE}={urllib.parse.quote(upstream_origin, safe="")}; '
                f'Path=/; SameSite=Lax')
        self.send_header('Content-Length', str(total))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            for c in chunks:
                self.wfile.write(c)
        except OSError:
            pass
        log.info('%s  -> %d  (%d bytes)', client, r.status_code, total)

    def do_GET(self):    self._forward()
    def do_HEAD(self):   self._forward()
    def do_POST(self):   self._forward()
    def do_PUT(self):    self._forward()
    def do_DELETE(self): self._forward()
    def do_PATCH(self):  self._forward()
    def do_OPTIONS(self):self._forward()


class ThreadingHTTPServer(socketserver.ThreadingMixIn,
                          http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Listeners
# ---------------------------------------------------------------------------

def _serve_http(host: str, port: int) -> None:
    srv = ThreadingHTTPServer((host, port), GatewayHandler)
    log.info('HTTP  listening on %s:%d', host, port)
    srv.serve_forever()


def _serve_https(host: str, port: int, cert: str, key: str) -> None:
    srv = ThreadingHTTPServer((host, port), GatewayHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log.info('HTTPS listening on %s:%d  (cert=%s)', host, port, cert)
    srv.serve_forever()


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description='URL-forwarding gateway')
    p.add_argument('--host', default='0.0.0.0',
                   help='bind interface (default 0.0.0.0)')
    p.add_argument('--http-port', type=int, default=DEFAULT_HTTP_PORT)
    p.add_argument('--https-port', type=int, default=DEFAULT_HTTPS_PORT)
    p.add_argument('--public-host', default='',
                   help='host or IP to embed in the self-signed cert '
                        'SAN (defaults to whatever the listener binds)')
    p.add_argument('--cert', default=None, help='TLS cert (PEM)')
    p.add_argument('--key',  default=None, help='TLS key (PEM)')
    return p.parse_args(argv)


def main() -> int:
    args = _parse_args()

    def on_sig(*_):
        log.info('signal received, exiting')
        sys.exit(130)
    signal.signal(signal.SIGINT, on_sig)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, on_sig)

    global _PUBLIC_HOST
    _PUBLIC_HOST = args.public_host

    public_host = args.public_host or _detect_public_host()
    cert, key = (args.cert, args.key) if (args.cert and args.key) \
        else _ensure_self_signed_cert(public_host)

    log.info('=' * 60)
    log.info('  URL-forwarding gateway')
    log.info('  GET/POST/... <host>/?url=<target>  →  proxied response')
    log.info('=' * 60)

    # HTTPS in main thread (so Ctrl+C in foreground stops the program);
    # HTTP in a daemon thread alongside.
    threading.Thread(
        target=_serve_http,
        args=(args.host, args.http_port),
        daemon=True,
    ).start()
    _serve_https(args.host, args.https_port, cert, key)
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
