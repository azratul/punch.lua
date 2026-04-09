-- punch/ws.lua
-- Minimal WebSocket client (RFC 6455).
--
-- Supports ws:// and wss://.  TLS for wss:// is handled by punch.tls (OpenSSL
-- memory BIOs).  Falls back gracefully if libssl is not found.
--
-- Works with vim.uv (Neovim) or luv (standalone).
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   ws.connect(url, opts, callback)
--     url      — "ws://host:port/path" or "wss://host:port/path"
--     opts     — { headers = {k=v}, timeout = ms }
--     callback(err, conn)
--
--   conn:send_text(str)        — send UTF-8 text frame (masked)
--   conn:send_binary(data)     — send binary frame (masked)
--   conn:on("message", fn)     — fn(opcode, data): opcode = "text"|"binary"
--   conn:on("close",   fn)     — fn(reason)
--   conn:close()
local M = {}

local uv  = (vim and (vim.uv or vim.loop)) or require("luv")
local bit = require("bit")
local band, bxor = bit.band, bit.bxor
local tls = require("punch.tls")

local schedule = (vim and vim.schedule) or function(fn) fn() end

-- ── Base64 (standard, for Sec-WebSocket-Key) ──────────────────────────────────

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function b64_encode(s)
  local res, i = {}, 1
  while i <= #s do
    local b1, b2, b3 = s:byte(i), s:byte(i+1) or 0, s:byte(i+2) or 0
    local n = b1*65536 + b2*256 + b3
    res[#res+1] = B64:sub(math.floor(n/262144)+1,    math.floor(n/262144)+1)
    res[#res+1] = B64:sub(math.floor(n/4096)%64+1,   math.floor(n/4096)%64+1)
    res[#res+1] = i+1 <= #s and B64:sub(math.floor(n/64)%64+1, math.floor(n/64)%64+1) or "="
    res[#res+1] = i+2 <= #s and B64:sub(n%64+1,      n%64+1) or "="
    i = i + 3
  end
  return table.concat(res)
end

local function make_client_key()
  local ok, crypto = pcall(require, "punch.crypto")
  local bytes
  if ok and crypto.available then
    bytes = crypto.random_bytes(16)
  else
    local t = {}
    for i = 1, 16 do t[i] = string.char(math.random(0, 255)) end
    bytes = table.concat(t)
  end
  return b64_encode(bytes)
end

-- ── URL parser ────────────────────────────────────────────────────────────────

-- Returns host, port, path, secure, err
local function parse_url(url)
  local scheme, rest
  if url:sub(1, 6) == "wss://" then
    scheme, rest = "wss", url:sub(7)
  elseif url:sub(1, 5) == "ws://" then
    scheme, rest = "ws",  url:sub(6)
  else
    return nil, nil, nil, nil, "URL must start with ws:// or wss://"
  end
  local authority = rest:match("^([^/]+)") or rest
  local path      = rest:sub(#authority + 1)
  if path == "" then path = "/" end
  local host, port_str = authority:match("^(.+):(%d+)$")
  if not host then
    host     = authority
    port_str = (scheme == "wss") and "443" or "80"
  end
  return host, tonumber(port_str), path, (scheme == "wss")
end

-- ── Frame encode ──────────────────────────────────────────────────────────────

-- opcode: 1 = text, 2 = binary.  Client → server frames MUST be masked (RFC §5.3).
local function encode_frame(payload, opcode)
  opcode = opcode or 2
  local len    = #payload
  local first  = 0x80 + opcode  -- FIN=1

  local header
  if len < 126 then
    header = string.char(first, 0x80 + len)
  elseif len < 65536 then
    header = string.char(first, 0xFE, math.floor(len/256), len%256)
  else
    header = string.char(first, 0xFF, 0, 0, 0, 0,
      math.floor(len/16777216)%256,
      math.floor(len/65536)%256,
      math.floor(len/256)%256,
      len%256)
  end

  local mk = { math.random(0,255), math.random(0,255),
               math.random(0,255), math.random(0,255) }
  local masked = {}
  for i = 1, len do
    masked[i] = string.char(bxor(payload:byte(i), mk[(i-1)%4+1]))
  end
  return header .. string.char(mk[1],mk[2],mk[3],mk[4]) .. table.concat(masked)
end

-- ── Frame decode (stateful) ───────────────────────────────────────────────────

-- Returns a function: reader(chunk) → { {opcode="text"|"binary"|"close", data=...}, ... }
local function new_frame_reader()
  local buf = ""
  return function(data)
    buf = buf .. data
    local frames = {}
    while true do
      if #buf < 2 then break end
      local b1, b2   = buf:byte(1), buf:byte(2)
      local opcode   = band(b1, 0x0F)
      local masked   = band(b2, 0x80) ~= 0
      local plen7    = band(b2, 0x7F)
      local ext      = (plen7 == 126) and 2 or (plen7 == 127) and 8 or 0
      local hdr_size = 2 + ext + (masked and 4 or 0)
      if #buf < hdr_size then break end

      local plen
      if     plen7 < 126  then plen = plen7
      elseif plen7 == 126 then plen = buf:byte(3)*256 + buf:byte(4)
      else
        plen = buf:byte(7)*16777216 + buf:byte(8)*65536
             + buf:byte(9)*256      + buf:byte(10)
      end
      if #buf < hdr_size + plen then break end

      local payload = buf:sub(hdr_size + 1, hdr_size + plen)
      if masked then
        local mk_pos = 2 + ext + 1
        local mk     = { buf:byte(mk_pos, mk_pos + 3) }
        local bytes  = {}
        for i = 1, plen do
          bytes[i] = string.char(bxor(payload:byte(i), mk[(i-1)%4+1]))
        end
        payload = table.concat(bytes)
      end

      buf = buf:sub(hdr_size + plen + 1)

      if opcode == 1 then
        frames[#frames+1] = { opcode = "text",   data = payload }
      elseif opcode == 2 then
        frames[#frames+1] = { opcode = "binary", data = payload }
      elseif opcode == 8 then
        frames[#frames+1] = { opcode = "close",  data = payload }
      end
      -- ping/pong (opcodes 9/10) ignored for simplicity
    end
    return frames
  end
end

-- ── Connection object ─────────────────────────────────────────────────────────

local function new_conn(tcp)
  local self = { _tcp = tcp, _cbs = {}, _closed = false }

  function self:on(event, fn)
    self._cbs[event] = fn
    return self
  end

  function self:_emit(event, ...)
    local fn = self._cbs[event]
    if fn then fn(...) end
  end

  function self:send_text(str)
    if self._closed then return end
    tcp:write(encode_frame(str, 1))
  end

  function self:send_binary(data)
    if self._closed then return end
    tcp:write(encode_frame(data, 2))
  end

  function self:close()
    if self._closed then return end
    self._closed = true
    if not tcp:is_closing() then tcp:close() end
  end

  return self
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- After TCP (and optional TLS) is established, perform the HTTP upgrade and
-- drive the WebSocket state machine.  `io` is either a raw uv.tcp or a TLS
-- adapter — both expose the same write/read_start/read_stop/is_closing/close API.
local function do_ws_upgrade(io, host, path, opts, callback)
  local ws_key = make_client_key()
  local state  = "handshaking"
  local hs_buf = ""
  local reader = new_frame_reader()
  local conn   = new_conn(io)

  local extra = ""
  for k, v in pairs(opts.headers or {}) do
    extra = extra .. k .. ": " .. v .. "\r\n"
  end

  io:write(table.concat({
    "GET " .. path .. " HTTP/1.1",
    "Host: " .. host,
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Key: " .. ws_key,
    "Sec-WebSocket-Version: 13",
    extra,
    "\r\n",
  }, "\r\n"))

  io:read_start(function(rerr, data)
    if rerr or not data then
      conn._closed = true
      schedule(function() conn:_emit("close", rerr or "eof") end)
      return
    end

    if state == "handshaking" then
      hs_buf = hs_buf .. data
      local hend = hs_buf:find("\r\n\r\n", 1, true)
      if not hend then return end

      local headers = hs_buf:sub(1, hend + 3)
      local rest    = hs_buf:sub(hend + 4)
      hs_buf        = nil

      if not headers:find("101") then
        conn._closed = true
        io:close()
        schedule(function()
          callback("WS upgrade rejected:\n" .. headers:sub(1, 200))
        end)
        return
      end

      state = "open"
      schedule(function() callback(nil, conn) end)
      if #rest > 0 then
        local frames = reader(rest)
        schedule(function()
          for _, f in ipairs(frames) do
            if f.opcode == "close" then
              conn._closed = true
              conn:_emit("close", "server closed")
            else
              conn:_emit("message", f.opcode, f.data)
            end
          end
        end)
      end
      return
    end

    -- state == "open"
    local frames = reader(data)
    schedule(function()
      for _, f in ipairs(frames) do
        if f.opcode == "close" then
          conn._closed = true
          conn:_emit("close", "server closed")
        else
          conn:_emit("message", f.opcode, f.data)
        end
      end
    end)
  end)
end

function M.connect(url, opts, callback)
  opts = opts or {}
  local host, port, path, secure, perr = parse_url(url)
  if perr then
    schedule(function() callback(perr) end)
    return
  end

  uv.getaddrinfo(host, nil, { socktype = "stream" }, function(err, res)
    if err or not res or #res == 0 then
      schedule(function()
        callback("could not resolve host '" .. host .. "': " .. tostring(err))
      end)
      return
    end

    local tcp = uv.new_tcp()
    tcp:connect(res[1].addr, port, function(cerr)
      if cerr then
        tcp:close()
        schedule(function() callback("TCP connect failed: " .. tostring(cerr)) end)
        return
      end

      if secure then
        tls.wrap(tcp, host, function(terr, adapter)
          if terr then
            schedule(function() callback(terr) end)
            return
          end
          do_ws_upgrade(adapter, host, path, opts, callback)
        end)
      else
        do_ws_upgrade(tcp, host, path, opts, callback)
      end
    end)
  end)
end

return M
