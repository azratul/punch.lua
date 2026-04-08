-- punch/punch.lua
-- UDP hole punching: coordinated STUN-based probing between two peers.
--
-- How it works:
--   Both peers simultaneously send STUN Binding Requests to each other's
--   public endpoint.  Each outgoing packet creates or refreshes a NAT mapping;
--   once both mappings exist the packets start getting through.  The hole is
--   considered punched when ANY UDP datagram from the remote arrives.
--
-- Works with vim.uv (Neovim) or luv (standalone).
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   punch.probe(handle, remote_addr, remote_port, opts, callback)
--
--     handle       — bound udp handle (from ice.gather)
--     remote_addr  — remote public IP string
--     remote_port  — remote public port number
--
--     opts (all optional):
--       interval   — ms between probe sends       (default: 500)
--       timeout    — ms total before giving up    (default: 5000)
--
--     callback(err, handle)
--       success: err=nil, handle=ready for data
--       failure: err="reason", handle=nil
local M = {}

local uv      = (vim and (vim.uv or vim.loop)) or require("luv")
local bit     = require("bit")
local band    = bit.band
local bxor    = bit.bxor
local stun    = require("punch.stun")
local log     = require("punch.log")

local schedule = (vim and vim.schedule) or function(fn) fn() end

local pack16  = stun._pack16
local pack32  = stun._pack32
local unpack16 = stun._unpack16
local MAGIC   = stun._MAGIC
local MAGIC_HI = stun._MAGIC_HI
local new_txid = stun._new_txid
local build_binding_request = stun._binding_request

local PROBE_INTERVAL_MS = 500
local PROBE_TIMEOUT_MS  = 5000

-- ── STUN Binding Response ─────────────────────────────────────────────────────

-- Detect a STUN message: top 2 bits of byte 1 are 0, magic cookie at bytes 5-8.
local function is_stun(data)
  if #data < 20 then return false end
  if band(data:byte(1), 0xC0) ~= 0 then return false end
  return stun._unpack32(data, 5) == MAGIC
end

-- Build a Binding Success Response for an incoming Binding Request.
local function build_response(txid, addr, port)
  local a, b, c, d = addr:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
  if not a then return nil end
  local ip32  = tonumber(a)*16777216 + tonumber(b)*65536
              + tonumber(c)*256      + tonumber(d)
  local xport = bxor(port,  MAGIC_HI)
  local xaddr = bxor(ip32,  MAGIC)

  local attr = pack16(0x0020) .. pack16(8)
            .. "\x00\x01"                    -- reserved, family IPv4
            .. pack16(xport) .. pack32(xaddr)

  return pack16(0x0101) .. pack16(#attr) .. pack32(MAGIC) .. txid .. attr
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- Probe a remote endpoint and return the handle when the hole is punched.
--
-- The probe loop:
--   1. Send a STUN Binding Request to remote every `interval` ms.
--   2. Listen for any incoming UDP.
--   3. If a Binding Request arrives from remote, respond (courtesy).
--   4. Stop on first packet from remote (hole punched) or on timeout.
function M.probe(handle, remote_addr, remote_port, opts, callback)
  opts = opts or {}

  local interval_ms = opts.interval or PROBE_INTERVAL_MS
  local timeout_ms  = opts.timeout  or PROBE_TIMEOUT_MS
  local done        = false
  local timers      = {}

  local function finish(err)
    if done then return end
    done = true
    for _, t in ipairs(timers) do
      if not t:is_closing() then t:close() end
    end
    -- We don't recv_stop here because the caller (channel.lua)
    -- will want to start its own recv_start.
    callback(err, err == nil and handle or nil)
  end

  local function send_probe()
    if done then return end
    log.debug("sending UDP probe to %s:%d", remote_addr, remote_port)
    handle:send(
      build_binding_request(new_txid()),
      remote_addr, remote_port,
      function(err)
        if err then log.debug("UDP send error: %s", tostring(err)) end
      end)
  end

  -- Listen for incoming UDP from the remote.
  handle:recv_start(function(recv_err, data, addr_tab)
    if done then return end
    if recv_err or not data then return end
    
    local src_addr = addr_tab and addr_tab.address
    local src_port = addr_tab and addr_tab.port

    if src_addr then
      log.debug("packet received from %s:%d (%d bytes)", src_addr, src_port or 0, #data)
    end

    -- Respond to Binding Requests so the remote can confirm their side.
    if src_addr and is_stun(data) and unpack16(data, 1) == 0x0001 then
      local resp = build_response(data:sub(9, 20), src_addr, src_port)
      if resp then
        handle:send(resp, src_addr, src_port, function() end)
      end
    end

    -- Any datagram from the target remote means the hole is punched.
    -- In local tests (127.0.0.1), some systems report '::ffff:127.0.0.1' or similar.
    local clean_src = src_addr and src_addr:gsub("^::ffff:", "")
    if not clean_src or clean_src == remote_addr then
      log.debug("hole punched — connection established with %s", remote_addr)
      schedule(function() finish(nil) end)
    end
  end)

  -- Start the probe loop.
  send_probe()

  local interval_t = uv.new_timer()
  timers[#timers+1] = interval_t
  interval_t:start(interval_ms, interval_ms, send_probe)

  local timeout_t = uv.new_timer()
  timers[#timers+1] = timeout_t
  timeout_t:start(timeout_ms, 0, function()
    schedule(function()
      finish("probe timed out after " .. timeout_ms .. " ms — NAT type may not support UDP hole punching")
    end)
  end)
end

return M
