-- punch/stun.lua
-- RFC 5389 STUN Binding client.
--
-- Sends a Binding Request to a STUN server over UDP and returns the
-- public (NAT-mapped) IP and port of the local socket.
--
-- Works with vim.uv (Neovim) or luv (standalone).
--
-- Usage:
--   local stun = require("punch.stun")
--   stun.discover({ server = "stun.l.google.com:19302" }, function(err, addr, port)
--     if err then error(err) end
--     print(addr, port)  -- e.g. "1.2.3.4", 54321
--   end)
local M = {}

local uv      = (vim and (vim.uv or vim.loop)) or require("luv")
local bit     = require("bit")
local band    = bit.band
local bxor    = bit.bxor
local rshift  = bit.rshift

-- Use immediate execution for schedule.
local schedule = function(fn) fn() end

-- ── Constants ─────────────────────────────────────────────────────────────────

local MAGIC     = 0x2112A442
local MAGIC_HI  = 0x2112        -- high 16 bits, used for XOR-MAPPED-ADDRESS port

local BIND_REQ_TYPE  = "\x00\x01"
local BIND_RESP_TYPE = 0x0101

local ATTR_MAPPED_ADDRESS     = 0x0001
local ATTR_XOR_MAPPED_ADDRESS = 0x0020

local DEFAULT_SERVER  = "stun.l.google.com"
local DEFAULT_PORT    = 19302
local DEFAULT_TIMEOUT = 3000   -- ms per attempt
local DEFAULT_RETRIES = 3

-- ── Binary helpers ────────────────────────────────────────────────────────────

local function pack16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function pack32(n)
  return string.char(
    math.floor(n / 16777216) % 256,
    math.floor(n / 65536)    % 256,
    math.floor(n / 256)      % 256,
    n % 256)
end

local function unpack16(s, i)
  return s:byte(i) * 256 + s:byte(i + 1)
end

local function unpack32(s, i)
  return s:byte(i)   * 16777216
       + s:byte(i+1) * 65536
       + s:byte(i+2) * 256
       + s:byte(i+3)
end

local function new_txid()
  local t = {}
  for i = 1, 12 do t[i] = string.char(math.random(0, 255)) end
  return table.concat(t)
end

-- ── STUN message encode/decode ────────────────────────────────────────────────

local function binding_request(txid)
  return BIND_REQ_TYPE   -- type: 0x0001
      .. pack16(0)        -- length: 0 (no attributes)
      .. pack32(MAGIC)    -- magic cookie
      .. txid             -- 12-byte transaction ID
end

-- Parse XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS from a STUN response.
-- Returns addr (string), port (number) or nil, nil.
local function parse_response(data, txid)
  if #data < 20 then return nil, nil end

  local msg_type  = unpack16(data, 1)
  local msg_len   = unpack16(data, 3)
  local resp_txid = data:sub(9, 20)

  if msg_type ~= BIND_RESP_TYPE then return nil, nil end
  if resp_txid ~= txid           then return nil, nil end

  local addr, port
  local pos = 21

  while pos + 3 <= 20 + msg_len do
    local atype = unpack16(data, pos)
    local alen  = unpack16(data, pos + 2)

    if atype == ATTR_XOR_MAPPED_ADDRESS then
      if data:byte(pos + 5) == 0x01 then  -- IPv4
        local xport = unpack16(data, pos + 6)
        local xaddr = unpack32(data, pos + 8)
        port = bxor(xport, MAGIC_HI)
        local a1 = bxor(band(rshift(xaddr, 24), 0xFF), band(rshift(MAGIC, 24), 0xFF))
        local a2 = bxor(band(rshift(xaddr, 16), 0xFF), band(rshift(MAGIC, 16), 0xFF))
        local a3 = bxor(band(rshift(xaddr,  8), 0xFF), band(rshift(MAGIC,  8), 0xFF))
        local a4 = bxor(band(xaddr,             0xFF), band(MAGIC,             0xFF))
        addr = a1 .. "." .. a2 .. "." .. a3 .. "." .. a4
        return addr, port  -- XOR-MAPPED-ADDRESS takes precedence; stop here
      end

    elseif atype == ATTR_MAPPED_ADDRESS and not addr then
      if data:byte(pos + 5) == 0x01 then  -- IPv4
        port = unpack16(data, pos + 6)
        local raw = unpack32(data, pos + 8)
        addr = math.floor(raw / 16777216) % 256 .. "."
            .. math.floor(raw / 65536)    % 256 .. "."
            .. math.floor(raw / 256)      % 256 .. "."
            .. raw % 256
      end
    end

    -- Attributes are padded to 4-byte boundaries
    local pad = alen % 4 ~= 0 and (4 - alen % 4) or 0
    pos = pos + 4 + alen + pad
  end

  return addr, port
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- Discover the public (NAT-mapped) IP:port by querying a STUN server.
--
-- opts (all optional):
--   server   — "host:port" or "host"  (default: stun.l.google.com:19302)
--   timeout  — ms per attempt         (default: 3000)
--   retries  — max retry count        (default: 3)
--   handle   — existing bound udp handle to reuse (default: creates a new one)
--              When provided, the caller owns the handle: this function calls
--              recv_stop() when done but never closes it.
--
-- callback(err, addr, port)
function M.discover(opts, callback)
  opts = opts or {}

  local server_str  = opts.server or DEFAULT_SERVER
  local server_host = server_str:match("^(.+):%d+$") or server_str
  local server_port = tonumber(server_str:match(":(%d+)$")) or DEFAULT_PORT
  local timeout_ms  = opts.timeout or DEFAULT_TIMEOUT
  local max_retries = opts.retries or DEFAULT_RETRIES

  local external = opts.handle ~= nil
  local udp      = opts.handle or uv.new_udp()
  local timers   = {}
  local attempt  = 0
  local done     = false

  local function finish(err, addr, port)
    if done then return end
    done = true
    for _, t in ipairs(timers) do
      if not t:is_closing() then t:close() end
    end
    udp:recv_stop()
    if not external and not udp:is_closing() then udp:close() end
    callback(err, addr, port)
  end

  local function send_attempt(server_addr)
    if done then return end
    attempt = attempt + 1

    local txid    = new_txid()
    local request = binding_request(txid)

    -- Re-register recv handler with the current txid for each attempt.
    udp:recv_stop()
    udp:recv_start(function(recv_err, data)
      if recv_err or not data then return end
      local addr, port = parse_response(data, txid)
      if addr and port then
        schedule(function() finish(nil, addr, port) end)
      end
    end)

    udp:send(request, server_addr, server_port, function(send_err)
      if send_err then
        schedule(function()
          finish("STUN send failed: " .. tostring(send_err))
        end)
      end
    end)

    local t = uv.new_timer()
    timers[#timers + 1] = t
    t:start(timeout_ms, 0, function()
      t:close()
      if done then return end
      if attempt < max_retries then
        send_attempt(server_addr)
      else
        schedule(function()
          finish("STUN timeout — no response after " .. max_retries .. " attempts")
        end)
      end
    end)
  end

  uv.getaddrinfo(server_host, nil, { socktype = "dgram" }, function(err, res)
    if err or not res or #res == 0 then
      schedule(function()
        finish("could not resolve STUN server '" .. server_host .. "': " .. tostring(err))
      end)
      return
    end
    send_attempt(res[1].addr)
  end)
end

-- ── Internal exports (for use by punch.ice) ──────────────────────────────────
-- Prefixed with _ to signal they are not part of the public API.
M._MAGIC             = MAGIC
M._MAGIC_HI          = MAGIC_HI
M._pack16            = pack16
M._pack32            = pack32
M._unpack16          = unpack16
M._unpack32          = unpack32
M._new_txid          = new_txid
M._binding_request   = binding_request

return M
