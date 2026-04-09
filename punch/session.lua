-- punch/session.lua
-- Session lifecycle orchestration.
--
-- Coordinates the full P2P connection flow:
--   gather → describe → exchange (out-of-band) → check → select → open channel
--
-- Both peers run the same code; there is no client/server asymmetry at this
-- layer.  The only difference is who publishes their description first, which
-- is determined by the application (e.g. the "host" publishes first).
--
-- ── State machine ─────────────────────────────────────────────────────────────
--
--   new → gathering → ready → connecting → open → closed
--
--   new        — just created, no I/O yet
--   gathering  — ice.gather() in progress
--   ready      — local description available; waiting for remote description
--   connecting — ice.check_pairs() in progress
--   open       — channel established, send/recv active
--   closed     — terminated (cleanly or with error)
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   local s = session.new(config)
--     config.stun          — STUN server "host:port"
--     config.relay         — relay broker URL "ws://host:port" (nil = no relay fallback)
--     config.relay_timeout — ms to wait for relay peer (default: relay module default)
--     config.key           — 32-byte AES key (nil = auto-derive from tokens)
--     config.port          — local UDP port (default: 0 = OS picks)
--     config.probe         — opts passed to punch.probe (interval, timeout)
--     config.timeout       — global session timeout in ms (0 / nil = no limit)
--
--   s:gather([callback])         — gather candidates; callback(err)
--   s:get_local_description()    → string | nil, err
--   s:set_remote_description(s)  — parse + start connectivity checks
--
--   s:on("open",    fn)  — fn()        channel is ready
--   s:on("message", fn)  — fn(data)    incoming payload
--   s:on("close",   fn)  — fn(reason)  session ended
--   s:on("error",   fn)  — fn(err)     non-fatal error (connection attempt failed, etc.)
--
--   s:send(data)         — send payload (only valid in "open" state)
--   s:close()            — shut down the session
--   s.state              — current state string
local M = {}

local ice     = require("punch.ice")
local signal  = require("punch.signal")
local channel = require("punch.channel")
local crypto  = require("punch.crypto")
local relay_m = require("punch.relay")
local log     = require("punch.log")

local uv       = (vim and (vim.uv or vim.loop)) or require("luv")
local schedule = function(fn) fn() end

-- ── Module-level helpers ──────────────────────────────────────────────────────

local function _random_token()
  local t = {}
  for i = 1, 8 do t[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(t)
end

-- Derive the session AES key for a given session object.
local function _derive_session_key(s)
  if not crypto.available or not crypto.ecdh_available then return nil end
  if s._ecdh and s._remote_desc and s._remote_desc.pub then
    local remote_pub, derr = crypto.b64_decode(s._remote_desc.pub)
    if remote_pub and #remote_pub == 32 then
      local key, kerr = crypto.ecdh_derive(s._ecdh, remote_pub)
      if key then return key end
    end
  end
  return nil
end

function M.new(config)
  config = config or {}

  local self = {
    state          = "new",
    _config        = config,
    _cbs           = {},
    _local_cands   = nil,
    _local_desc    = nil,
    _remote_desc   = nil,
    _handle        = nil,
    _channel       = nil,
    _token         = nil,
    _ecdh          = nil,   -- { pub, priv } ephemeral X25519 keypair
    _timeout_timer = nil,
    _winning_pair  = nil,   -- ICE pair that succeeded; nil until "open"
  }

  -- ── Event helpers ──────────────────────────────────────────────────────────

  local function _err(code, msg)
    return { code = code, message = msg }
  end

  function self:on(event, fn)
    self._cbs[event] = fn
    return self
  end

  function self:_emit(event, ...)
    local fn = self._cbs[event]
    if fn then fn(...) end
  end

  function self:_set_state(s)
    local prev = self.state
    self.state = s
    -- Cancel the global timeout once we reach a terminal or success state.
    if (s == "open" or s == "closed") and self._timeout_timer then
      if not self._timeout_timer:is_closing() then
        self._timeout_timer:close()
      end
      self._timeout_timer = nil
    end
    if s ~= prev then
      schedule(function() self:_emit("state_change", s, prev) end)
    end
  end

  -- Start a one-shot timer that closes the session if it hasn't opened yet.
  function self:_start_timeout()
    local ms = config.timeout
    if not ms or ms <= 0 then return end
    local timer = uv.new_timer()
    self._timeout_timer = timer
    timer:start(ms, 0, function()
      if self.state ~= "open" and self.state ~= "closed" then
        self:close()
        schedule(function()
          self:_emit("error", _err("TIMEOUT", "session timed out after " .. ms .. " ms"))
        end)
      end
    end)
  end

  -- ── Gather ─────────────────────────────────────────────────────────────────

  -- Gather local candidates.  Moves to "ready" state on success.
  -- callback is optional; errors are also emitted via on("error").
  function self:gather(callback)
    if self.state ~= "new" then
      local e = _err("INVALID_STATE", "gather called in state '" .. self.state .. "'")
      schedule(function()
        if callback then callback(e) end
        self:_emit("error", e)
      end)
      return
    end

    self:_set_state("gathering")
    self._token = _random_token()
    log.init(config)
    self:_start_timeout()

    -- Generate an ephemeral X25519 keypair for ECDH key exchange.
    if crypto.ecdh_available then
      local kp, kerr = crypto.ecdh_keygen()
      if kp then
        self._ecdh = kp
      else
        schedule(function()
          self:_emit("error", _err("CRYPTO_WARN", "ECDH keygen warning: " .. tostring(kerr)))
        end)
      end
    end

    ice.gather({ port = config.port, stun = config.stun },
      function(err, cands, handle)
        if err then
          self:_set_state("closed")
          local e = _err("GATHER_FAILED", err)
          schedule(function()
            if callback then callback(e) end
            self:_emit("error", e)
          end)
          return
        end

        self._local_cands = cands
        self._handle      = handle
        self:_set_state("ready")

        -- Pre-build the local description string (include ECDH public key if available).
        local desc_table = {
          token      = self._token,
          candidates = cands,
          pub        = self._ecdh and crypto.b64_encode(self._ecdh.pub) or nil,
        }
        local str, serr  = signal.encode(desc_table)
        if not str then
          self:_set_state("closed")
          if handle and not handle:is_closing() then handle:close() end
          local e = _err("SIGNAL_ENCODE", serr)
          schedule(function()
            if callback then callback(e) end
            self:_emit("error", e)
          end)
          return
        end

        self._local_desc = str
        schedule(function()
          if callback then callback(nil) end
        end)

        -- If the remote description arrived before gathering completed, proceed.
        if self._remote_desc then
          self:_start_checks()
        end
      end)
  end

  -- ── Description exchange ───────────────────────────────────────────────────

  function self:get_local_description()
    if not self._local_desc then
      return nil, _err("NOT_READY", "local description not ready — call gather() first")
    end
    return self._local_desc
  end

  function self:set_remote_description(str)
    if self._remote_desc then
      self:_emit("error", _err("INVALID_STATE", "remote description already set"))
      return
    end
    if self.state == "closed" then
      self:_emit("error", _err("INVALID_STATE", "cannot set remote description on closed session"))
      return
    end

    local desc, err = signal.decode(str)
    if not desc then
      self:_emit("error", _err("INVALID_SIGNAL", "invalid remote description: " .. tostring(err)))
      return
    end

    -- Token validation:
    --   • must be a 16-char hex string
    --   • must not be our own token (prevents self-connection loops)
    local token = desc.token or ""
    if not token:match("^%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$") then
      self:_emit("error", _err("INVALID_SIGNAL", "remote description has invalid token format"))
      return
    end
    if self._token and token == self._token then
      self:_emit("error", _err("SELF_CONNECTION", "remote description token matches local token"))
      return
    end

    self._remote_desc = desc

    if self.state == "ready" then
      self:_start_checks()
    elseif self.state == "gathering" then
      -- Will be picked up at the end of gather().
    else
      -- already checked closed above, so this is just in case of future states
      self:_emit("error", _err("INVALID_STATE", "set_remote_description called in state '" .. self.state .. "'"))
    end
  end

  -- ── Connectivity checks ────────────────────────────────────────────────────

  -- Return the ICE candidate pair that was selected when the session opened.
  -- Returns nil if the session is not yet open or used a relay channel.
  function self:get_selected_pair()
    return self._winning_pair
  end

  -- Helper: open a channel from a winning UDP pair.
  function self:_open_udp_channel(winning_pair, handle)
    self._winning_pair = winning_pair
    local key = config.key or _derive_session_key(self)

    local ch = channel.new_udp(handle, winning_pair.remote_cand.addr,
      winning_pair.remote_cand.port,
      { key = key, mode = "direct",
        keepalive_interval = config.keepalive_interval,
        peer_timeout       = config.peer_timeout })

    ch:on("data",  function(data) self:_emit("message", data) end)
    ch:on("close", function(reason)
      self:_set_state("closed")
      self:_emit("close", reason)
    end)

    self._channel = ch
    self:_set_state("open")
    schedule(function() self:_emit("open") end)
  end

  -- Helper: attempt relay fallback after all direct pairs fail.
  function self:_try_relay(direct_err)
    local relay_url   = config.relay
    local relay_token
    for _, c in ipairs(self._remote_desc and self._remote_desc.candidates or {}) do
      if c.type == "relay" and c.relay_token then
        relay_token = c.relay_token
        break
      end
    end

    if not relay_url or not relay_token then
      -- No relay configured or no relay token in remote description.
      self:_set_state("closed")
      if self._handle and not self._handle:is_closing() then
        self._handle:recv_stop()
        self._handle:close()
        self._handle = nil
      end
      schedule(function() self:_emit("close", direct_err) end)
      return
    end

    relay_m.connect(relay_url, relay_token, { timeout = config.relay_timeout },
      function(err, relay_conn)
        if self.state == "closed" then return end  -- timed out meanwhile
        if err then
          self:_set_state("closed")
          if self._handle and not self._handle:is_closing() then
            self._handle:recv_stop()
            self._handle:close()
            self._handle = nil
          end
          schedule(function()
            self:_emit("close", "direct failed (" .. direct_err .. "); relay also failed: " .. err)
          end)
          return
        end

        local key = config.key or _derive_session_key(self)

        local ch = channel.new_relay(relay_conn, { key = key })

        ch:on("data",  function(data) self:_emit("message", data) end)
        ch:on("close", function(reason)
          self:_set_state("closed")
          self:_emit("close", reason)
        end)

        self._channel = ch
        self:_set_state("open")
        schedule(function() self:_emit("open") end)
      end)
  end

  function self:_start_checks()
    if self.state ~= "ready" then return end
    self:_set_state("connecting")
    log.debug("starting connectivity checks with %d remote candidates", #self._remote_desc.candidates)

    local remote_cands = self._remote_desc.candidates
    local pairs        = ice.make_pairs(self._local_cands, remote_cands)
    log.debug("%d candidate pairs generated", #pairs)

    ice.check_pairs(pairs, self._handle, config.probe or {},
      function(err, winning_pair, handle)
        log.debug("check_pairs result: %s", err or "success")
        if self.state == "closed" then return end  -- timed out meanwhile
        if err then
          -- All direct pairs failed — try relay if configured.
          self:_try_relay(err)
          return
        end

        self:_open_udp_channel(winning_pair, handle)
      end)
  end

  -- ── Send / Close ───────────────────────────────────────────────────────────

  function self:send(data)
    if type(data) ~= "string" then
      self:_emit("error", _err("INVALID_ARG", "send() expects a string payload"))
      return
    end
    if self.state ~= "open" or not self._channel then
      self:_emit("error", _err("INVALID_STATE", "cannot send in state '" .. self.state .. "'"))
      return
    end
    self._channel:send(data)
  end

  function self:close()
    if self.state == "closed" then return end
    self:_set_state("closed")
    if self._channel then
      self._channel:close()
      self._channel = nil
    elseif self._handle and not self._handle:is_closing() then
      self._handle:recv_stop()
      self._handle:close()
    end
    self._handle = nil
    schedule(function() self:_emit("close", "closed by local peer") end)
  end

  return self
end

return M
