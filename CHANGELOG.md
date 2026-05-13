# Changelog

All notable changes to **bupt-netaccount-transfer-service** are documented in
this file. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-13

Initial public release.

### Added — OTP automation (half 1)

- `local/mitm_capture.py` — A-side orchestrator that flips HKCU into a
  one-shot proxy state, spawns `mitmdump` with the bundled addon, and
  forwards the lifted captive-portal cookie to B over a mTLS link.
- `local/_otp_addon.py` — mitmproxy addon that sniffs the first `/otp`
  request on the configured captive-portal host, lifts its `Cookie`
  header, parses the 10-digit account ID from the homepage HTML, and
  POSTs both back to the parent orchestrator.
- `server/otp_poller.py` — B-side `/otp` polling daemon. Long-lived
  `requests.Session` polling at the cadence the portal's own JS uses;
  raises a `refresh_needed` event back to A when the session breaks.
- `server/atrust_setup.py` — B-side aTrust UI driver via `pywinauto`.
  Nine-step flow with batched-keystroke OTP entry, post-typing freshness
  recheck, `UIATreeReadError` auto-retry (kill aTrust + re-launch up to
  `MAX_UIA_RETRIES`), and a post-login intranet-probe keepalive loop.
- `server/record_popup.py` — passive UIA event recorder for debugging
  aTrust success-card popups.
- `shared/_link.py` — mTLS helpers: self-signed cert generation,
  length-prefixed JSON `send` / `serve` over a single common cert pair.
- `shared/_spawn.py` — Windows-detached process spawner with
  `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB`,
  plus UTF-8 env for the child so logs render correctly in mixed-locale
  terminals.
- `shared/_runner.sh` — bash worker-registry helpers: detach-spawn,
  Ctrl+B background / Ctrl+C kill foreground attach, orphan tail/awk
  cleanup, Windows-aware `_pid_alive` via `tasklist`.
- `shared/_env.ps1` — PowerShell helper for HKCU proxy backup/restore
  and process-name based `kill_all`.
- `run_a.sh`, `run_b.sh`, `run_test_local.sh`, `run_test_seperate.sh`
  — Git-Bash launchers; `takeover` / `stop` / `status` subcommands;
  CLI passthrough for `--port` / `--peer-port` / `--peer-host` /
  `--target-host` / `--vpn-url`.

### Added — Access gateway (half 2)

- `gateway/server.py` — HTTPS-terminating URL-forwarding proxy. Listens
  on 80/443, accepts `?url=<target>` requests, terminates TLS with a
  locally minted self-signed CA (no client-side CA install required if
  you're willing to click through the browser warning), re-fetches the
  upstream over a fresh `Python ssl` handshake (which aTrust's
  per-process SSL hook routes through the tunnel correctly), and
  streams the response back verbatim. Three-tier upstream resolution
  for sub-resources (query > Referer > `__gw_origin` cookie) so
  CSS-referenced fonts / images / AJAX still flow through the gateway.
  Set-Cookie `Domain=` stripping; absolute Location header rewriting.
- `gateway/tcp_forward.py` — generic static TCP port forwarder. Used
  to expose intranet SSH hosts through the gateway box without TLS
  interception (raw splice — works because aTrust doesn't inspect
  plain TCP).

### Documentation

- Bilingual README (`README.md` English / `README.zh-CN.md` Chinese),
  cross-linked, with project name + BUPT context badges, architecture
  diagram, prerequisites, per-half setup walkthroughs, operational
  notes, file map, contribution guide.
- `LICENSE` (MIT).

### Known limitations

- Absolute upstream URLs inside HTML bodies are not rewritten — the
  gateway is fine for single-URL fetches and pages with mostly relative
  links, but clicking an absolute link to `bupt.edu.cn` inside a
  returned page bypasses the gateway. Pages with predominantly
  relative URLs (most modern web apps) work.
- WebSocket / Server-Sent Events / chunked streaming responses are
  buffered whole-body before relay.
- The gateway has no built-in authentication. Lock down at firewall +
  cloud security group level.
- `run_b.sh` does not forward `--keepalive-url`; edit the constant in
  `server/atrust_setup.py` or invoke that script directly.
