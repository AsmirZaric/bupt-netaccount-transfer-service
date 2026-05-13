"""Internal: mitmproxy addon loaded by mitm_capture.py's mitmdump subprocess.

Part of bupt-netaccount-transfer-service. Tuned for the BUPT netaccount
captive portal at netaccount.bupt.edu.cn; the homepage parsing assumes
a 10-digit numeric student ID embedded in the rendered HTML.

Default behavior: pass everything through unchanged.

When the capture-flag file exists, the addon enters capture mode for
`/otp` requests on the captive-portal host configured via the
`MITM_TARGET_HOST` environment variable (set by mitm_capture.py before
spawning mitmdump):

  - On the first /otp request, lift the `Cookie:` header
  - Attach the most recently extracted account ID (10-digit number
    parsed out of the previously seen `/` homepage response, if any)
  - POST {cookie, username} back to mitm_capture.py at 127.0.0.1:9999/cookies
  - Reply 204 to the browser (so server-side cookie state doesn't rotate)

mitm_capture.py owns the flag lifecycle: it creates the flag at startup and
on `refresh_needed` events from Module B, and removes it after receiving the
captured cookie back via the local callback.

Account-ID extraction (response hook on /):
  The homepage HTML embeds the 10-digit account ID multiple times
  (nav-link label, table cell, etc.). We match the first 10-digit run
  between HTML tags, which is robust against codepage / encoding
  garbling because account IDs are pure ASCII digits.
"""

import logging
import os
import re
import sys
import urllib.parse
import urllib.request
from mitmproxy import http

# Add sibling `shared/` to sys.path so `_paths` resolves when mitmdump
# loads this addon as a script (mitmdump doesn't propagate the parent's
# PYTHONPATH reliably across all builds).
_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shared')
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import _paths

CALLBACK_URL = 'http://127.0.0.1:9999/cookies'
# Captive-portal hostname; set by the parent mitm_capture.py via env var.
TARGET_HOST = os.environ.get('MITM_TARGET_HOST', '')
OTP_PATH = '/otp'
HOME_PATH = '/'

CAPTURE_FLAG = _paths.CAPTURE_FLAG

# 10-digit student ID extraction. Try strict pattern first (digits alone
# between tags, e.g. `<div class="col-9">\n  XXXXXXXXXX\n</div>`), then a
# looser fallback for in-text occurrences (e.g. `<span>您好: YYYYYYYYYY</span>`).
USERNAME_RES = (
    re.compile(rb'>\s*(\d{10})\s*<'),
    re.compile(rb'(?<!\d)(\d{10})(?!\d)'),
)


def _extract_username(body: bytes) -> str:
    for pat in USERNAME_RES:
        m = pat.search(body)
        if m:
            return m.group(1).decode('ascii')
    return ''

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

log = logging.getLogger('otp_capture')

# Sticky across requests until overwritten by the next homepage response.
state = {'username': ''}


def response(flow: http.HTTPFlow):
    """Mine the captive portal's `/` homepage HTML for the account ID. Pure
    observation -- we do NOT mutate this response."""
    if flow.request.pretty_host != TARGET_HOST:
        return
    path = (flow.request.path or '').split('?', 1)[0]
    if path != HOME_PATH:
        return
    if flow.response.status_code != 200:
        return
    ct = flow.response.headers.get('Content-Type', '')
    if 'html' not in ct.lower():
        return
    body = flow.response.content or b''
    username = _extract_username(body)
    if username:
        if state['username'] != username:
            log.warning('[otp_capture] extracted username=%s (from / HTML)', username)
        state['username'] = username


def request(flow: http.HTTPFlow):
    if flow.request.pretty_host != TARGET_HOST:
        return

    path = (flow.request.path or '').split('?', 1)[0]
    if path != OTP_PATH:
        return

    if not os.path.exists(CAPTURE_FLAG):
        # Pass-through mode -- Module B's polling loop is healthy.
        return

    cookie_header = flow.request.headers.get('Cookie', '')
    username = state.get('username', '')
    log.warning('[otp_capture] /otp captured (cookie len=%d, username=%s)',
                len(cookie_header), username or '<unknown>')

    if cookie_header:
        try:
            payload = urllib.parse.urlencode({
                'cookie':   cookie_header,
                'username': username,
            }).encode('utf-8')
            req = urllib.request.Request(
                CALLBACK_URL,
                data=payload,
                method='POST',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
            )
            _NO_PROXY_OPENER.open(req, timeout=2).read()
        except Exception as e:
            log.error('[otp_capture] forward to orchestrator failed: %s', e)

    flow.response = http.Response.make(
        204, b'', {'Content-Type': 'application/json'}
    )
