-- punch/relay.lua
-- Relay fallback when direct UDP hole punching fails.
--
-- Architecture: both peers connect to a relay broker via WebSocket, identify
-- with a shared relay token, and the broker forwards binary frames between them.
-- The relay is fully transparent to the data channel — payloads are already
-- encrypted by channel.lua before reaching this layer.
--
-- ── Broker protocol (minimal, custom) ────────────────────────────────────────
--
--   All control messages are JSON TEXT frames.
--   Data is forwarded as BINARY frames, opaque to the broker.
--
--   Client → Broker:  {"join":"<relay_token>"}
--   Broker → Client:  {"ready":true}              once both peers have joined
--   Broker → Client:  {"error":"<reason>"}        on failure
--   Client → Broker:  {"leave":true}              graceful disconnect
--
-- The broker implementation is intentionally minimal (~60 lines of
-- Node.js/Go).  See docs/broker.md for a reference server.
--
-- ── Replaceability ───────────────────────────────────────────────────────────
--
--   relay.connect() returns a relay_conn object.  channel.new_relay() accepts
--   any object with the same shape, so this module can be swapped for a
--   TURN-based or Iroh-based implementation without touching session.lua.
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   relay.connect(broker_url, relay_token, opts, callback)
--     broker_url   — "ws://host:port"
--     relay_token  — shared secret that matches the two peers on the broker
--     opts.timeout — ms to wait for the peer to join (default: 30000)
--     callback(err, relay_conn)
--
--   relay.make_token()
--     → random 8-byte hex relay token (use one per session)
--
--   relay.make_candidate(broker_url, relay_token)
--     → { type="relay", addr=host, port=N, relay_token=token }
--       ready to add to the local description's candidate list
local M = {}

local ws       = require("punch.ws")
local schedule = (vim and vim.schedule) or function(fn) fn() end

local DEFAULT_TIMEOUT_MS = 30000

-- ── Minimal JSON control message parser ──────────────────────────────────────
-- Only needs to handle the three broker → client messages.

local function parse_control(text)
  if text:find('"ready"') and text:find('true') then
    return "ready"
  end
  local err = text:match('"error"%s*:%s*"([^"]*)"')
  if err then return "error", err end
  return nil
end

-- ── relay_conn object ─────────────────────────────────────────────────────────
-- Wraps a WebSocket connection and exposes the same interface as channel
-- expects: send(data), on("data"/"close"), close().

local function new_relay_conn(ws_conn)
  local self   = { _cbs = {}, _closed = false, _ws = ws_conn }

  function self:on(event, fn)
    self._cbs[event] = fn
    return self
  end

  function self:_emit(event, ...)
    local fn = self._cbs[event]
    if fn then fn(...) end
  end

  function self:send(data)
    if self._closed then return end
    self._ws:send_binary(data)
  end

  function self:close()
    if self._closed then return end
    self._closed = true
    self._ws:send_text('{"leave":true}')
    self._ws:close()
  end

  -- Wire up WS events → relay_conn events.
  ws_conn:on("message", function(opcode, data)
    if opcode == "binary" then
      schedule(function() self:_emit("data", data) end)
    end
    -- TEXT frames after "ready" are unexpected; ignore silently.
  end)

  ws_conn:on("close", function(reason)
    self._closed = true
    schedule(function() self:_emit("close", reason or "relay disconnected") end)
  end)

  return self
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- Connect to a relay broker and wait for the remote peer to join.
--
-- Both peers call relay.connect() with the same broker_url and relay_token.
-- The broker matches them and sends {"ready":true} to both; only then does
-- the callback fire.
--
-- callback(err, relay_conn)
function M.connect(broker_url, relay_token, opts, callback)
  if type(opts) == "function" then
    callback, opts = opts, {}
  end
  opts = opts or {}

  local timeout_ms = opts.timeout or DEFAULT_TIMEOUT_MS
  local done       = false
  local timer      = nil

  local function finish(err, conn)
    if done then return end
    done = true
    if timer and not timer:is_closing() then timer:close() end
    callback(err, conn)
  end

  ws.connect(broker_url, {}, function(err, conn)
    if err then
      finish("relay WS connect failed: " .. tostring(err))
      return
    end

    -- Timeout while waiting for the peer to join.
    local uv = (vim and (vim.uv or vim.loop)) or require("luv")
    timer = uv.new_timer()
    timer:start(timeout_ms, 0, function()
      conn:close()
      schedule(function()
        finish("relay timeout — peer did not join within " .. timeout_ms .. " ms")
      end)
    end)

    conn:on("close", function(reason)
      finish("relay broker disconnected before ready: " .. tostring(reason))
    end)

    conn:on("message", function(opcode, data)
      if opcode ~= "text" then return end
      local kind, detail = parse_control(data)

      if kind == "ready" then
        -- Both peers are connected; hand back the relay_conn.
        -- Re-wire the message handler to forward binary data only.
        conn:on("message", function() end)  -- replaced by relay_conn's handler
        finish(nil, new_relay_conn(conn))

      elseif kind == "error" then
        conn:close()
        finish("relay broker error: " .. tostring(detail))
      end
    end)

    -- Identify ourselves on the broker.
    conn:send_text('{"join":"' .. relay_token .. '"}')
  end)
end

-- Generate a random relay token (different from the session token).
function M.make_token()
  local t = {}
  for i = 1, 8 do t[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(t)
end

-- Build a relay candidate entry suitable for adding to a description.
--
-- broker_url   — "ws://relay.example.com:8080"
-- relay_token  — token from M.make_token()
function M.make_candidate(broker_url, relay_token)
  local host = broker_url:match("^ws://([^:/]+)")
  local port  = tonumber(broker_url:match(":(%d+)$")) or 80
  if not host then
    return nil, "invalid broker_url: " .. tostring(broker_url)
  end
  return {
    type        = "relay",
    addr        = host,
    port        = port,
    relay_token = relay_token,
    priority    = 0,  -- lowest: only used when direct fails
  }
end

return M
