-- punch/channel.lua
-- Reliable-ish data channel abstraction.
--
-- Wraps the underlying transport (direct UDP or relay WebSocket) and exposes
-- a uniform send/receive interface to the application.  The app does not need
-- to know whether the connection is direct or relayed, or whether encryption
-- is active.
--
-- ── Wire format ───────────────────────────────────────────────────────────────
--
-- Every datagram (before optional AES-GCM encryption) carries a 1-byte frame
-- type prefix:
--
--   \x01  data frame  — payload follows; forwarded to the application
--   \x00  keepalive   — no payload; resets the dead-peer timer, not forwarded
--
-- The prefix is encrypted with the payload when a key is configured, so it is
-- opaque to observers.  Two peers must run the same library version.
--
-- ── Keepalive and dead-peer detection (UDP channel only) ─────────────────────
--
-- The UDP channel fires a keepalive frame every `keepalive_interval` ms.  The
-- same timer checks whether any packet has been received from the peer within
-- `peer_timeout` ms; if not, the channel is closed with reason "peer timeout".
-- Any packet from the peer (data or keepalive) resets the receive timestamp.
--
-- ── Payload limit ────────────────────────────────────────────────────────────
--
-- send() rejects payloads larger than MAX_PAYLOAD bytes to catch accidental
-- misuse early.  The limit applies to the pre-encryption plaintext.
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   ch = channel.new_udp(handle, peer_addr, peer_port, opts)
--     opts.key                — 32-byte AES key (nil = plaintext)
--     opts.mode               — "direct" | "relay" (informational, default "direct")
--     opts.keepalive_interval — ms between keepalives (default: 5000)
--     opts.peer_timeout       — ms of silence before closing (default: 30000)
--     opts.max_payload        — max plaintext bytes per send() call (default: 65000)
--
--   ch = channel.new_relay(relay_conn, opts)
--     opts.key                — 32-byte AES key (nil = plaintext)
--     opts.max_payload        — max plaintext bytes per send() call (default: 65000)
--
--   ch:send(payload)       — send a binary payload to the peer
--   ch:on("data",  fn)     — fn(payload) on each incoming payload
--   ch:on("close", fn)     — fn(reason)  on disconnect / error
--   ch:close()             — shut down
--   ch.mode                — "direct" | "relay"
--   ch.peer_addr           — remote IP string
--   ch.peer_port           — remote port number
local M = {}

local uv     = (vim and (vim.uv or vim.loop)) or require("luv")
local crypto = require("punch.crypto")
local schedule = (vim and vim.schedule) or function(fn) fn() end

local MAX_PAYLOAD        = 65000  -- bytes; guard against accidental misuse
local DEFAULT_KA_MS      = 5000   -- keepalive interval
local DEFAULT_DEAD_MS    = 30000  -- dead-peer timeout

local FRAME_DATA = "\x01"
local FRAME_KA   = "\x00"

-- ── Internal helpers ──────────────────────────────────────────────────────────

local function new_channel(mode)
  return {
    mode    = mode or "direct",
    _cbs    = {},
    _closed = false,
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
  local key          = opts.key
  local ka_interval  = opts.keepalive_interval or DEFAULT_KA_MS
  local dead_timeout = opts.peer_timeout       or DEFAULT_DEAD_MS
  local max_payload  = opts.max_payload        or MAX_PAYLOAD
  local self         = new_channel(opts.mode or "direct")

  self.peer_addr  = peer_addr
  self.peer_port  = peer_port
  self._handle    = handle
  self._last_recv = uv.now()  -- assume peer alive at creation

  self.on = ch_on

  local ka_timer = nil

  local function stop_timer()
    if ka_timer and not ka_timer:is_closing() then ka_timer:close() end
    ka_timer = nil
  end

  local function do_close(reason)
    if self._closed then return end
    self._closed = true
    stop_timer()
    handle:recv_stop()
    if not handle:is_closing() then handle:close() end
    schedule(function() ch_emit(self, "close", reason) end)
  end

  -- Send a raw (already framed+encrypted) datagram to the peer.
  local function raw_send(data)
    handle:send(data, peer_addr, peer_port, function() end)
  end

  -- Build and send a keepalive frame.
  local function send_keepalive()
    if self._closed then return end
    local data = FRAME_KA
    if key then
      local enc = crypto.encrypt(key, data)
      if not enc then return end
      data = enc
    end
    raw_send(data)
  end

  -- Start the combined keepalive + dead-peer timer.
  ka_timer = uv.new_timer()
  ka_timer:start(ka_interval, ka_interval, function()
    if self._closed then return end
    if uv.now() - self._last_recv >= dead_timeout then
      do_close("peer timeout")
      return
    end
    send_keepalive()
  end)

  self.close = function(s)
    do_close("closed by local peer")
  end

  self.send = function(s, payload)
    if s._closed then return end
    if type(payload) ~= "string" then return end
    if #payload > max_payload then
      do_close(string.format("payload too large: %d > %d bytes", #payload, max_payload))
      return
    end
    local data = FRAME_DATA .. payload
    if key then
      local enc, err = crypto.encrypt(key, data)
      if not enc then
        do_close("encrypt error: " .. tostring(err))
        return
      end
      data = enc
    end
    raw_send(data)
  end

  -- Start receiving.
  handle:recv_start(function(err, data, addr_tab)
    if self._closed then return end

    if err then
      do_close(err)
      return
    end

    -- libuv fires with nil data for zero-length datagrams — not EOF, ignore.
    if not data then return end

    -- Only accept traffic from the known peer.
    local src_addr = addr_tab and addr_tab.address
    if src_addr then
      src_addr = src_addr:gsub("^::ffff:", "")
      if src_addr ~= peer_addr then return end
    end

    -- Any packet from peer resets the dead-peer clock.
    self._last_recv = uv.now()

    local payload = data
    if key then
      local dec = crypto.decrypt(key, data)
      if not dec then return end  -- bad tag: drop silently (stray / replay)
      payload = dec
    end

    -- Parse frame type.
    local ftype = payload:sub(1, 1)
    if ftype == FRAME_KA then
      return  -- keepalive: timer already reset above, nothing to deliver
    elseif ftype == FRAME_DATA then
      payload = payload:sub(2)
    else
      return  -- unknown frame type: drop
    end

    schedule(function() ch_emit(self, "data", payload) end)
  end)

  return self
end

-- ── Relay channel ────────────────────────────────────────────────────────────
--
-- Wraps a relay_conn (from relay.lua) with the same channel interface.
-- The relay_conn must expose: send(data), on("data"/"close", fn), close().
-- Keepalive is not needed here: the underlying WebSocket/TCP layer handles
-- liveness.  The frame prefix is applied for consistency.

function M.new_relay(relay_conn, opts)
  opts = opts or {}
  local key         = opts.key
  local max_payload = opts.max_payload or MAX_PAYLOAD
  local self        = new_channel("relay")

  self.peer_addr = opts.peer_addr or "relay"
  self.peer_port = opts.peer_port or 0
  self._relay    = relay_conn

  self.on = ch_on

  self.send = function(s, payload)
    if s._closed then return end
    if type(payload) ~= "string" then return end
    if #payload > max_payload then
      schedule(function()
        if not s._closed then
          s._closed = true
          ch_emit(s, "close", string.format("payload too large: %d > %d bytes", #payload, max_payload))
        end
      end)
      return
    end
    local data = FRAME_DATA .. payload
    if key then
      local enc, err = crypto.encrypt(key, data)
      if not enc then
        schedule(function()
          if not s._closed then
            s._closed = true
            ch_emit(s, "close", "encrypt error: " .. tostring(err))
          end
        end)
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
      local dec = crypto.decrypt(key, data)
      if not dec then return end  -- bad tag: drop silently
      payload = dec
    end

    local ftype = payload:sub(1, 1)
    if ftype == FRAME_KA then
      return  -- keepalive from relay peer: ignore
    elseif ftype == FRAME_DATA then
      payload = payload:sub(2)
    else
      return
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
