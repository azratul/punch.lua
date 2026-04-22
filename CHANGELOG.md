# Changelog

## [0.3.1] - 2026-04-22

### Fixed
- `session`: relay consumer peers (`relay_is_consumer = true`) no longer generate
  their own relay token/candidate during `gather()`. `_try_relay` now reads the
  broker owner's token from the remote description for these peers, ensuring both
  sides join the same relay room. Previously both peers used independent tokens and
  never paired at the broker.
- `relay.make_candidate`: port is now correctly extracted from URLs that include a
  path component (e.g. `ws://host:PORT/relay`). The previous `:(%d+)$` regex failed
  because the string ended with `/relay`, not a digit, so port always fell back to 80.

---

## [0.3.0] - 2026-04-21

### Added
- `signaling_server`: `/relay` WebSocket broker endpoint — pairs two peers sharing
  the same token and forwards opaque binary frames between them. Enables relay
  fallback without a separate server process.
- `session`: relay candidate injected into the local description during `gather()`
  when `config.relay` is set; `_try_relay()` falls back through the broker after
  all direct ICE pairs fail.
- `relay`: `relay.make_candidate()` helper for constructing relay description entries.

### Fixed
- `ws`: HTTP upgrade request ended with an extra `\r\n`, causing the server to
  parse the first bytes of the join frame as a malformed WebSocket frame.

### Tests
- 5 new integration tests for the relay broker (100/100 pass).

---

## [0.2.1] - 2026-04-07

### Fixed
- `tls`: declare `SSL_METHOD` typedef before use in `ffi.cdef` (NixOS / strict FFI).

---

## [0.2.0] - 2026-04-07

### Added
- `punch/tls.lua`: shared TLS wrapping extracted from `ws.lua`.
- `signaling_server`: HTTPS support in `fetch_host` / `post_guest`; configurable
  bind host via `config.host`.
- `channel`: 1-byte frame prefix (`\x01` data / `\x00` keepalive); UDP keepalive
  timer; dead-peer detection; 65 KB payload size limit.
- `session`: `state_change` event; `get_selected_pair()`.
- `ice`: `opts.stun` accepts a list of servers with sequential fallback.

### Breaking
- Wire format changed (frame prefix byte) — peers must run the same MINOR version.

---

## [0.1.0] - 2026-03-28

Initial release: STUN, ICE-lite candidate gathering, UDP hole punching,
AES-256-GCM channel encryption, HTTP signaling server, WebSocket client.
