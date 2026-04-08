# punch.lua

**Pure-Lua P2P NAT Traversal & Encrypted Channels**

`punch.lua` is a lightweight library for establishing direct UDP connections between peers behind NAT/Firewalls without manual port forwarding, VPNs, or external tunneling binaries.

Designed for LuaJIT scripts, automation tools, or **Neovim** plugins requiring secure P2P communication.

## Features

- **NAT Traversal**: Implements coordinated UDP Hole Punching.
- **Protocols**: Public endpoint discovery via **STUN** (RFC 5389) and **ICE-lite** candidate logic.
- **Security**: End-to-end encrypted channels using **AES-256-GCM** (via OpenSSL/FFI).
- **Resilience**: Automatic fallback to **WebSocket Relay** when direct traversal is impossible (e.g., symmetric NATs).
- **Asynchronous**: Built on the `luv` (libuv) event loop for non-blocking I/O.

## Installation

Install it directly via **LuaRocks**:

```bash
luarocks install punch
```

### System Requirements
- **LuaJIT**: Required for FFI support.
- **OpenSSL**: Must be installed on the system for encryption and WSS support.
- **libuv**: Provided by `luv` or `vim.uv` (built-in Neovim).

## Quick Start (Out-of-Band Signaling)

Since `punch.lua` is a pure P2P library, you only need to exchange a single string (the **Session Description**) between peers via any medium (chat, email, QR code, etc.).

### Both Peers:
```lua
local p2p = require("punch")

-- 1. Initialize the P2P session
local s = p2p.start({ stun = "stun.l.google.com:19302" })

-- 2. Get your local description and share it with the other peer
local my_desc = s:get_local_description()
print("Send this to your peer:", my_desc)

-- 3. Once you get THEIR description, set it to start the connection
-- (In a real app, you'd receive this string from the other peer)
s:set_remote_description(their_desc)

-- 4. Handle connection events
s:on("open", function()
  print("Connected via P2P UDP!")
  s:send("Hello from the other side of the NAT")
end)

s:on("message", function(data)
  print("Received encrypted message:", data)
end)
```

### Optional: WebSocket Relay Fallback
If direct UDP traversal is impossible (e.g., behind strict Symmetric NATs), you can provide a **Relay Broker** URL. The library will automatically fall back to it if the UDP punch fails:

```lua
local s = p2p.start({
  stun = "stun.l.google.com:19302",
  relay = "wss://your-relay-broker.com" -- Optional fallback
})
```

## Project Structure

- `punch/init.lua`: Main public API.
- `punch/punch.lua`: UDP hole punching probe loop.
- `punch/crypto.lua`: AES-GCM encryption and X25519 handshake.
- `punch/ws.lua`: Minimal WebSocket client with TLS support.
- `chat.lua`: Interactive P2P chat example application.

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

## License

This project is licensed under the **GNU GPLv3**. This ensures the software remains free, and any derivative works must also be open-sourced under the same license.

---
Built with ❤️ by [azratul](https://github.com/azratul)
