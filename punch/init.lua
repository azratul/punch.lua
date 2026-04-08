-- punch — pure-Lua P2P NAT traversal.
--
-- Establishes direct UDP connections between peers behind NAT without
-- requiring port forwarding, VPNs, or external tunneling binaries.
-- Falls back to a relay when the NAT type does not allow direct traversal.
--
-- Works with vim.uv (Neovim ≥ 0.10) or luv (standalone LuaJIT).
--
-- ── Quick start ───────────────────────────────────────────────────────────────
--
--   local p2p = require("punch")
--
--   -- Both peers run the same code.
--   local s = p2p.start({ stun = "stun.l.google.com:19302" })
--
--   -- Step 1: get your local description and share it out-of-band.
--   local desc = s:get_local_description()
--   -- → send `desc` to the other peer via chat, URL fragment, etc.
--
--   -- Step 2: receive their description and hand it over.
--   s:set_remote_description(their_desc)
--
--   -- Step 3: handle events.
--   s:on("open",    function()      print("connected!")          end)
--   s:on("message", function(data)  print("got:", data)          end)
--   s:on("close",   function(why)   print("closed:", why)        end)
--   s:on("error",   function(err)   print("error:", err)         end)
--
--   -- Step 4: send data once open.
--   s:on("open", function() s:send("hello!") end)
--
-- ── Config ────────────────────────────────────────────────────────────────────
--
--   stun          — STUN server "host:port"         (default: stun.l.google.com:19302)
--   relay         — relay broker URL "ws://…"       (default: nil — no relay fallback)
--   relay_timeout — ms to wait for relay peer        (default: 30000)
--   key           — 32-byte AES-256 key              (default: auto-derived from tokens)
--   port          — local UDP port                   (default: 0 = OS picks)
--   probe         — { interval, timeout }             (defaults: 500 ms, 5000 ms)
--   timeout       — global session timeout in ms     (default: 0 = no limit)
--
-- ── Session object ────────────────────────────────────────────────────────────
--
--   s:get_local_description()      → string  (share with remote peer)
--   s:set_remote_description(str)  — triggers connectivity checks
--   s:on(event, fn)                — "open" | "message" | "close" | "error"
--   s:send(data)                   — binary payload (valid only when open)
--   s:close()                      — terminate the session
--   s.state                        — "new"|"gathering"|"ready"|"connecting"|"open"|"closed"
--
-- ── Low-level modules ─────────────────────────────────────────────────────────
--
--   require("punch.session")  — session lifecycle
--   require("punch.ice")      — candidate gathering, pairing, selection
--   require("punch.punch")    — UDP hole punching probe loop
--   require("punch.stun")     — STUN Binding client (RFC 5389)
--   require("punch.signal")   — description encode/decode
--   require("punch.channel")  — data channel abstraction
--   require("punch.crypto")   — AES-256-GCM encryption
--   require("punch.relay")    — relay fallback (stub)
local M = {}

-- Seed the random number generator.
math.randomseed(os.time() + (tonumber(tostring({}):match("0x%x+")) or 0))

local session = require("punch.session")

-- Start a new P2P session.
--
-- Automatically begins candidate gathering.  The session moves to "ready"
-- state once gathering completes; register callbacks before calling start()
-- or use get_local_description() after the "ready" state is reached.
--
-- Returns the session object immediately (gathering is async).
function M.start(config)
  local s = session.new(config)
  s:gather()  -- fire and forget; errors surface via on("error")
  return s
end

-- Expose low-level modules for advanced use.
M.session = session
M.ice     = require("punch.ice")
M.stun    = require("punch.stun")
M.signal  = require("punch.signal")
M.channel = require("punch.channel")
M.crypto  = require("punch.crypto")
M.relay   = require("punch.relay")

return M
