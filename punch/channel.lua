-- punch/channel.lua
-- Reliable-ish data channel abstraction.
--
-- Wraps the underlying transport (direct UDP or relay WebSocket) and exposes
-- a uniform send/receive interface to the application.  The app does not need
-- to know whether the connection is direct or relayed, or whether encryption
-- is active.
--
-- Encryption: if a crypto context (key) is provided, every payload is
-- encrypted on send and decrypted on receive using AES-256-GCM.
--
-- UDP note: UDP is not reliable.  For the use cases this library targets
-- (collaborative text editing, cursor sharing) occasional packet loss is
-- acceptable.  If the application needs reliability, it should implement
-- its own sequence numbers and retransmission on top of channel:send().
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   ch = channel.new_udp(handle, peer_addr, peer_port, opts)
--     opts.key  — 32-byte AES key (nil = plaintext)
--     opts.mode — "direct" | "relay" (informational, default "direct")
--
--   ch:send(payload)       — send a binary payload to the peer
--   ch:on("data",  fn)     — fn(payload) on each incoming payload
--   ch:on("close", fn)     — fn(reason)  on disconnect / error
--   ch:close()             — shut down
--   ch.mode                — "direct" | "relay"
--   ch.peer_addr           — remote IP string
--   ch.peer_port           — remote port number
local M = {}

local crypto   = require("punch.crypto")
local schedule = (vim and vim.schedule) or function(fn) fn() end

-- ── Internal helpers ──────────────────────────────────────────────────────────

local function new_channel(mode)
  return {
    mode     = mode or "direct",
    _cbs     = {},
    _closed  = false,
  }
end

local function ch_on(self, event, fn)
  self._cbs[event] = fn
  return self
end

local function ch_emit(self, event, ...)
  local fn = self._cbs[event]
  if fn then fn(...) end
end

-- ── UDP channel ───────────────────────────────────────────────────────────────

-- Create a channel over a connected (hole-punched) UDP handle.
function M.new_udp(handle, peer_addr, peer_port, opts)
  opts = opts or {}
  local key  = opts.key
  local self = new_channel(opts.mode or "direct")

  self.peer_addr = peer_addr
  self.peer_port = peer_port
  self._handle   = handle

  self.on    = ch_on
  self.close = function(s)
    if s._closed then return end
    s._closed = true
    s._handle:recv_stop()
    if not s._handle:is_closing() then s._handle:close() end
  end

  self.send = function(s, payload)
    if s._closed then return end
    local data = payload
    if key then
      local enc, err = crypto.encrypt(key, payload)
      if not enc then
        schedule(function() ch_emit(s, "close", "encrypt error: " .. tostring(err)) end)
        return
      end
      data = enc
    end
    s._handle:send(data, peer_addr, peer_port, function() end)
  end

  -- Start receiving.
  handle:recv_start(function(err, data, addr_tab)
    if self._closed then return end

    if err then
      schedule(function()
        self._closed = true
        ch_emit(self, "close", err)
      end)
      return
    end

    -- libuv fires the UDP recv callback with nil data as an internal
    -- notification (e.g. zero-length datagram).  This is not EOF — ignore it.
    if not data then return end

    -- Only accept traffic from the known peer.
    local src_addr = addr_tab and addr_tab.address
    if src_addr then
      src_addr = src_addr:gsub("^::ffff:", "")
      if src_addr ~= peer_addr then return end
    end

    local payload = data
    if key then
      local dec, derr = crypto.decrypt(key, data)
      if not dec then
        -- Bad tag: drop silently (could be a stray packet or replay).
        return
      end
      payload = dec
    end

    schedule(function() ch_emit(self, "data", payload) end)
  end)

  return self
end

-- ── Relay channel ────────────────────────────────────────────────────────────
--
-- Wraps a relay_conn (from relay.lua) with the same channel interface.
-- The relay_conn must expose: send(data), on("data"/"close", fn), close().

function M.new_relay(relay_conn, opts)
  opts = opts or {}
  local key  = opts.key
  local self = new_channel("relay")

  -- Expose peer info from the relay candidate if provided.
  self.peer_addr = opts.peer_addr or "relay"
  self.peer_port = opts.peer_port or 0
  self._relay    = relay_conn

  self.on = ch_on

  self.send = function(s, payload)
    if s._closed then return end
    local data = payload
    if key then
      local enc, err = crypto.encrypt(key, payload)
      if not enc then
        schedule(function() ch_emit(s, "close", "encrypt error: " .. tostring(err)) end)
        return
      end
      data = enc
    end
    s._relay:send(data)
  end

  self.close = function(s)
    if s._closed then return end
    s._closed = true
    s._relay:close()
  end

  relay_conn:on("data", function(data)
    if self._closed then return end
    local payload = data
    if key then
      local dec, derr = crypto.decrypt(key, data)
      if not dec then
        -- Bad tag: drop silently.
        return
      end
      payload = dec
    end
    schedule(function() ch_emit(self, "data", payload) end)
  end)

  relay_conn:on("close", function(reason)
    if self._closed then return end
    self._closed = true
    schedule(function() ch_emit(self, "close", reason or "relay closed") end)
  end)

  return self
end

return M
