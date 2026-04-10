# punch.lua

**Pure-Lua P2P NAT Traversal & Encrypted Channels**

`punch.lua` is a lightweight library for establishing direct UDP connections between peers behind NAT/firewalls without manual port forwarding, VPNs, or external tunneling binaries.

Designed for LuaJIT scripts, automation tools, or **Neovim** plugins requiring secure P2P communication.

## Features

- **NAT Traversal**: Coordinated UDP hole punching via STUN (RFC 5389) and ICE-lite candidate logic.
- **Security**: End-to-end encrypted channels using **AES-256-GCM** + **X25519 ECDH** key exchange (via OpenSSL FFI). No pre-shared key required.
- **Resilience**: Automatic fallback to a **WebSocket relay broker** when symmetric NATs block direct traversal. UDP keepalives + dead-peer detection.
- **HTTP Signaling**: Optional built-in local HTTP signaling server — expose it with ngrok for internet-wide rendezvous without a separate backend.
- **Asynchronous**: Non-blocking I/O via `luv` (libuv). Works with `vim.uv`/`vim.loop` (Neovim ≥ 0.10) or standalone `luv`.

## Installation

```bash
luarocks install punch
```

### Requirements
- **LuaJIT** with FFI support
- **OpenSSL** (`libssl` + `libcrypto`) for encryption, HTTPS, and WSS
- **libuv** via `luv` (LuaRocks) or `vim.uv` (Neovim built-in)

## Quick Start

Candidate gathering is **asynchronous**. Register your callbacks first, then start the session. When gathering completes the session enters the `"ready"` state and `get_local_description()` becomes available.

```lua
local uv  = require("luv")
local p2p = require("punch")

local s = p2p.start({
  stun = { "stun.l.google.com:19302", "stun1.l.google.com:19302" },
})

-- Step 1: once gathering is done, share your description out-of-band.
s:on("state_change", function(new)
  if new == "ready" then
    local desc = s:get_local_description()
    print("Send this to your peer:", desc)
  end
end)

-- Step 2: after receiving the remote description from your peer:
--   s:set_remote_description(their_desc)

s:on("open", function()
  local pair = s:get_selected_pair()
  if pair then
    print(string.format("P2P open: %s:%d → %s:%d",
      pair.local_cand.addr,  pair.local_cand.port,
      pair.remote_cand.addr, pair.remote_cand.port))
  end
  s:send("Hello!")
end)

s:on("message", function(data) print("Got:", data) end)
s:on("close",   function(why)  print("Closed:", why) end)
s:on("error",   function(err)  print("Error:", err.message or err) end)

uv.run()
```

### Config reference

| Key | Default | Description |
|-----|---------|-------------|
| `stun` | `"stun.l.google.com:19302"` | STUN server `"host:port"` or a list — tried in order |
| `relay` | `nil` | Relay broker `"ws://…"` (no relay fallback if nil) |
| `relay_timeout` | `30000` | ms to wait for relay peer |
| `key` | auto | 32-byte AES-256 key (auto-derived from ECDH if nil) |
| `port` | `0` | Local UDP port (0 = OS picks) |
| `probe` | `{interval=500, timeout=5000}` | Hole-punch probe timing (ms) |
| `timeout` | `0` | Global session timeout in ms (0 = no limit) |
| `keepalive_interval` | `5000` | ms between UDP keepalive pings |
| `peer_timeout` | `30000` | ms of silence before the session is closed |
| `debug` | `false` | Write structured logs to `debug_log` path |
| `debug_log` | `"/tmp/punch.log"` | Log file path (when `debug = true`) |

### Session API

| Method / property | Description |
|-------------------|-------------|
| `s:get_local_description()` | Returns the description string to share with the remote peer. Available after the `"ready"` state. |
| `s:set_remote_description(str)` | Parses the remote description and starts connectivity checks. |
| `s:on(event, fn)` | Register a callback. Events: `"open"`, `"message"`, `"close"`, `"error"`, `"state_change"` |
| `s:get_selected_pair()` | Returns `{local_cand, remote_cand}` for the winning ICE pair, or `nil` if relay. |
| `s:send(data)` | Send a binary payload (only valid in `"open"` state). |
| `s:close()` | Terminate the session. |
| `s.state` | Current state: `"new"` → `"gathering"` → `"ready"` → `"connecting"` → `"open"` → `"closed"` |

**`state_change` event:** `fn(new_state, old_state)` — fired on every state transition.

## HTTP Signaling Server

For internet-wide testing without a dedicated backend, `punch.lua` includes a minimal HTTP signaling server you can expose via [ngrok](https://ngrok.com/) or any other tunneling service.

**Host:**
```lua
local sig = require("punch.signaling_server")

local srv = sig.new({ port = 0 })  -- srv.url → "http://127.0.0.1:PORT"
srv:set_host_desc(s:get_local_description())

srv:on_guest(function(slot, guest_desc)
  s:set_remote_description(guest_desc)
end)
-- In another terminal: ngrok http PORT
-- Share the https://...ngrok-free.app URL with the guest
```

**Guest:**
```lua
local sig = require("punch.signaling_server")

sig.fetch_host("https://xxxx.ngrok-free.app", 60000, function(err, host_desc, slot)
  s:set_remote_description(host_desc)
  sig.post_guest("https://xxxx.ngrok-free.app", slot, s:get_local_description(),
    function(post_err) end)
end)
```

HTTPS is handled transparently when the URL scheme is `https://` (requires OpenSSL).

### Relay fallback

When direct UDP traversal fails (symmetric NAT, strict firewall), the session automatically connects through a relay broker:

```lua
local s = p2p.start({
  stun  = "stun.l.google.com:19302",
  relay = "wss://your-relay-broker.com",
})
```

See `docs/broker.md` for a reference broker implementation (~60 lines of Node.js or Go).

## Project Structure

| Module | Purpose |
|--------|---------|
| `punch/init.lua` | Public API: `p2p.start(config)` |
| `punch/session.lua` | State machine; orchestrates gather → check → open |
| `punch/ice.lua` | Candidate gathering, pairing, priority, connectivity checks |
| `punch/stun.lua` | STUN Binding request/response (RFC 5389) |
| `punch/punch.lua` | UDP hole-punch probe loop |
| `punch/signal.lua` | Encode/decode description JSON |
| `punch/channel.lua` | Data channel: frame prefix, AES-GCM, keepalive, dead-peer timer |
| `punch/crypto.lua` | AES-256-GCM + X25519 via LuaJIT FFI → OpenSSL |
| `punch/relay.lua` | WebSocket relay fallback |
| `punch/ws.lua` | Minimal WebSocket client (text + binary), optional TLS |
| `punch/tls.lua` | TLS wrapper over a `uv` TCP handle using OpenSSL memory BIOs |
| `punch/signaling_server.lua` | Local HTTP signaling server + HTTPS client helpers |
| `punch/log.lua` | Structured debug logging to file |

## Testing

The project uses [busted](https://lunarmodules.github.io/busted/) for unit and integration tests.

Install dependencies (once):

```bash
luarocks --lua-version 5.1 install busted --local
luarocks --lua-version 5.1 install luv --local
eval "$(luarocks --lua-version 5.1 path --bin)"
```

Run the full suite:

```bash
busted
```

Run a single spec:

```bash
busted spec/crypto_spec.lua
```

## License

This project is licensed under the **GNU GPLv3**. Any derivative works must also be open-sourced under the same license.
