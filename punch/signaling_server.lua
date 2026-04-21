-- punch/signaling_server.lua
-- Minimal local HTTP signaling server for peer description exchange.
--
-- Runs on localhost:PORT.  The caller exposes it externally (e.g. via an SSH
-- reverse-proxy tunnel) and shares the resulting URL.  The server only lives
-- for the handshake phase — stop it once all punch sessions are open.
--
-- Wire protocol (plain HTTP/1.1, no WebSocket):
--
--   GET  /desc/host
--     Long-polls until the host description is available.
--     Response body  : raw description JSON string
--     Response header: X-Slot: <hex16>  (server-assigned slot for this guest)
--
--   PUT  /desc/:slot
--     Guest posts their description to the slot they received above.
--     Request body   : raw description JSON string
--     Response body  : {"ok":true}
--
--   DELETE /
--     Stop the server gracefully.
--     Response body  : {"ok":true}
--
-- ── Host-side API (in-process) ────────────────────────────────────────────────
--
--   local sig = require("punch.signaling_server")
--
--   local srv, err = sig.new({ port = 0 })
--   -- srv.url  → "http://127.0.0.1:PORT"
--   srv:set_host_desc(desc_str)           -- publish host description
--   srv:on_guest(fn)                      -- fn(slot, desc_str) per guest
--   srv:stop()
--
-- ── Guest-side API (HTTP client) ──────────────────────────────────────────────
--
--   sig.fetch_host(server_url, timeout_ms, callback)
--     callback(err, host_desc_str, slot_id)
--
--   sig.post_guest(server_url, slot_id, desc_str, callback)
--     callback(err)
local M = {}

local uv       = (vim and (vim.uv or vim.loop)) or require("luv")
local bit      = require("bit")
local log      = require("punch.log")
local tls      = require("punch.tls")
local schedule = (vim and vim.schedule) or function(fn) fn() end

local DEFAULT_TIMEOUT = 30000
local MAX_REQUEST     = 65536   -- hard cap: descriptions are ~500 bytes

-- ── SHA-1 (pure Lua, for WebSocket Sec-WebSocket-Accept) ─────────────────────

local function sha1(msg)
  local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
  local lshift, rol            = bit.lshift, bit.rol
  local function u32(n) return band(n, 0xFFFFFFFF) end

  local len = #msg
  msg = msg .. "\x80"
  while #msg % 64 ~= 56 do msg = msg .. "\x00" end
  local bl = len * 8
  msg = msg .. string.char(0, 0, 0, 0,
    math.floor(bl / 0x1000000) % 256,
    math.floor(bl / 0x10000)   % 256,
    math.floor(bl / 0x100)     % 256,
    bl % 256)

  local h0, h1, h2, h3, h4 =
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

  for i = 1, #msg, 64 do
    local w = {}
    for j = 0, 15 do
      local o = i + j * 4
      w[j] = u32(bor(lshift(msg:byte(o), 24), lshift(msg:byte(o + 1), 16),
                     lshift(msg:byte(o + 2), 8), msg:byte(o + 3)))
    end
    for j = 16, 79 do
      w[j] = rol(bxor(w[j - 3], w[j - 8], w[j - 14], w[j - 16]), 1)
    end

    local a, b, c, d, e = h0, h1, h2, h3, h4
    for j = 0, 79 do
      local f, k
      if j < 20 then
        f = bor(band(b, c), band(bnot(b), d)); k = 0x5A827999
      elseif j < 40 then
        f = bxor(b, c, d); k = 0x6ED9EBA1
      elseif j < 60 then
        f = bor(band(b, c), band(b, d), band(c, d)); k = 0x8F1BBCDC
      else
        f = bxor(b, c, d); k = 0xCA62C1D6
      end
      local t = u32(rol(a, 5) + f + e + k + w[j])
      e = d; d = c; c = rol(b, 30); b = a; a = t
    end
    h0 = u32(h0 + a); h1 = u32(h1 + b); h2 = u32(h2 + c)
    h3 = u32(h3 + d); h4 = u32(h4 + e)
  end

  local function b4(n)
    return string.char(
      math.floor(n / 0x1000000) % 256, math.floor(n / 0x10000) % 256,
      math.floor(n / 0x100) % 256,     n % 256)
  end
  return b4(h0) .. b4(h1) .. b4(h2) .. b4(h3) .. b4(h4)
end

-- ── Base64 (standard alphabet, for Sec-WebSocket-Accept) ─────────────────────

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function b64_encode(s)
  local res, i = {}, 1
  while i <= #s do
    local b1, b2, b3 = s:byte(i), s:byte(i + 1) or 0, s:byte(i + 2) or 0
    local n = b1 * 65536 + b2 * 256 + b3
    res[#res + 1] = B64:sub(math.floor(n / 262144) + 1,    math.floor(n / 262144) + 1)
    res[#res + 1] = B64:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    res[#res + 1] = i + 1 <= #s and B64:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1) or "="
    res[#res + 1] = i + 2 <= #s and B64:sub(n % 64 + 1, n % 64 + 1) or "="
    i = i + 3
  end
  return table.concat(res)
end

local WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

local function ws_accept_key(client_key)
  return b64_encode(sha1(client_key .. WS_GUID))
end

-- ── WebSocket server-side framing ─────────────────────────────────────────────
-- Server → client frames are unmasked (RFC 6455 §5.1).

local function ws_encode_server(payload, opcode)
  opcode = opcode or 2
  local len   = #payload
  local first = 0x80 + opcode
  local header
  if len < 126 then
    header = string.char(first, len)
  elseif len < 65536 then
    header = string.char(first, 126, math.floor(len / 256), len % 256)
  else
    header = string.char(first, 127, 0, 0, 0, 0,
      math.floor(len / 0x1000000) % 256, math.floor(len / 0x10000) % 256,
      math.floor(len / 0x100) % 256,     len % 256)
  end
  return header .. payload
end

-- Client → server frames are masked; this reader handles both masked and unmasked.
local function new_ws_frame_reader()
  local buf = ""
  return function(data)
    buf = buf .. data
    local frames = {}
    while true do
      if #buf < 2 then break end
      local b1, b2 = buf:byte(1), buf:byte(2)
      local opcode = bit.band(b1, 0x0F)
      local masked = bit.band(b2, 0x80) ~= 0
      local plen7  = bit.band(b2, 0x7F)
      local ext    = (plen7 == 126) and 2 or (plen7 == 127) and 8 or 0
      local hdr    = 2 + ext + (masked and 4 or 0)
      if #buf < hdr then break end

      local plen
      if     plen7 < 126  then plen = plen7
      elseif plen7 == 126 then plen = buf:byte(3) * 256 + buf:byte(4)
      else
        plen = buf:byte(7) * 16777216 + buf:byte(8) * 65536
             + buf:byte(9) * 256      + buf:byte(10)
      end
      if #buf < hdr + plen then break end

      local payload = buf:sub(hdr + 1, hdr + plen)
      if masked then
        local mp  = 2 + ext + 1
        local mk  = { buf:byte(mp, mp + 3) }
        local out = {}
        for i = 1, plen do
          out[i] = string.char(bit.bxor(payload:byte(i), mk[(i - 1) % 4 + 1]))
        end
        payload = table.concat(out)
      end
      buf = buf:sub(hdr + plen + 1)

      if     opcode == 1 then frames[#frames + 1] = { opcode = "text",   data = payload }
      elseif opcode == 2 then frames[#frames + 1] = { opcode = "binary", data = payload }
      elseif opcode == 8 then frames[#frames + 1] = { opcode = "close",  data = payload }
      end
    end
    return frames
  end
end

-- ── WebSocket relay broker ────────────────────────────────────────────────────
--
-- Endpoint: GET /relay  (with Upgrade: websocket)
--
-- Protocol (same as relay.lua client expects):
--   peer → broker : TEXT  {"join":"<relay_token>"}
--   broker → peer : TEXT  {"ready":true}    (once both peers have joined)
--   broker → peer : TEXT  {"error":"<msg>"} (on failure)
--   peer → broker : BINARY (data frame)     forwarded opaque to the other peer
--   peer → broker : TEXT  {"leave":true}    graceful disconnect
--
-- The broker is token-matched: two peers with the same relay_token are paired.
-- All data frames are forwarded without inspection (already AES-GCM encrypted
-- by channel.lua on both ends).

local function handle_ws_relay(client, state, ws_key)
  client:write(
    "HTTP/1.1 101 Switching Protocols\r\n" ..
    "Upgrade: websocket\r\n" ..
    "Connection: Upgrade\r\n" ..
    "Sec-WebSocket-Accept: " .. ws_accept_key(ws_key) .. "\r\n\r\n"
  )

  local reader   = new_ws_frame_reader()
  local my_token = nil
  local room_ref = {}  -- room_ref[1] set once this peer is paired
  local closed   = false

  local function send_text(s)
    if not client:is_closing() then
      client:write(ws_encode_server(s, 1))
    end
  end

  local function send_binary(s)
    if not client:is_closing() then
      client:write(ws_encode_server(s, 2))
    end
  end

  local function on_close()
    if closed then return end
    closed = true
    if my_token and not room_ref[1] then
      state.relay_rooms[my_token] = nil
    end
    local room = room_ref[1]
    if room then
      local other = (room.a_client == client) and room.b_client or room.a_client
      if other and not other:is_closing() then other:close() end
    end
    if not client:is_closing() then client:close() end
  end

  local function process(data)
    for _, f in ipairs(reader(data)) do
      if f.opcode == "close" then
        on_close(); return

      elseif f.opcode == "binary" then
        local room = room_ref[1]
        if room then
          local fwd = (room.a_client == client) and room.b_send or room.a_send
          fwd(f.data)
        end

      elseif f.opcode == "text" then
        if f.data:find('"leave"', 1, true) then
          on_close(); return
        end
        if not my_token then
          local t = f.data:match('"join"%s*:%s*"([^"]*)"')
          if not t or t == "" then
            send_text('{"error":"expected join message with relay_token"}')
            on_close(); return
          end
          my_token = t
          local entry = state.relay_rooms[t]
          if not entry then
            state.relay_rooms[t] = {
              a_send_text   = send_text,
              a_send_binary = send_binary,
              a_client      = client,
              a_room_ref    = room_ref,
            }
          else
            state.relay_rooms[t] = nil
            local room = {
              a_send   = entry.a_send_binary,
              a_client = entry.a_client,
              b_send   = send_binary,
              b_client = client,
            }
            entry.a_room_ref[1] = room
            room_ref[1]         = room
            entry.a_send_text('{"ready":true}')
            send_text('{"ready":true}')
          end
        end
      end
    end
  end

  client:read_start(function(rerr, data)
    if rerr or not data then on_close(); return end
    process(data)
  end)
end

-- ── Helpers ───────────────────────────────────────────────────────────────────

local function random_slot()
  local t = {}
  for i = 1, 8 do t[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(t)
end

-- Parse the first line + headers from a raw HTTP buffer.
-- Returns method, path, content_length, body_start_offset  or  nil (incomplete).
local function parse_http_head(buf)
  local hdr_end = buf:find("\r\n\r\n", 1, true)
  if not hdr_end then return nil end
  local head    = buf:sub(1, hdr_end - 1)
  local method, path = head:match("^(%u+) (%S+) HTTP/%d+%.%d+")
  if not method then return nil end
  local clen = tonumber(head:match("[Cc]ontent%-[Ll]ength: *(%d+)")) or 0
  return method, path, clen, hdr_end + 4
end

-- Parse HTTP response status + headers from a buffer.
-- Returns status_code, x_slot, content_length, body_start  or  nil.
local function parse_http_response(buf)
  local hdr_end = buf:find("\r\n\r\n", 1, true)
  if not hdr_end then return nil end
  local head  = buf:sub(1, hdr_end - 1)
  local code  = tonumber(head:match("^HTTP/%d+%.%d+ (%d+)"))
  if not code then return nil end
  local slot  = head:match("[Xx]%-[Ss]lot: *([%x]+)")
  local clen  = tonumber(head:match("[Cc]ontent%-[Ll]ength: *(%d+)")) or 0
  return code, slot, clen, hdr_end + 4
end

local STATUS = { [200]="OK", [404]="Not Found", [405]="Method Not Allowed",
                 [408]="Request Timeout", [413]="Payload Too Large" }

local function send_response(client, code, extra_headers, body)
  if client:is_closing() then return end
  body = body or ""
  local hdr = string.format("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n",
    code, STATUS[code] or "Error", #body)
  if extra_headers then hdr = hdr .. extra_headers end
  client:write(hdr .. "\r\n" .. body, function()
    if not client:is_closing() then client:close() end
  end)
end

local function ok(client, body, extra_headers)
  send_response(client, 200, extra_headers, body)
end

local function err_resp(client, code, msg)
  send_response(client, code, nil, '{"error":"' .. msg:gsub('"', '\\"') .. '"}')
end

-- ── Per-connection handler ────────────────────────────────────────────────────

local function handle_connection(client, state, timeout_ms)
  local buf = ""

  client:read_start(function(rerr, data)
    if rerr or not data then
      if not client:is_closing() then client:close() end
      return
    end

    buf = buf .. data
    if #buf > MAX_REQUEST then
      err_resp(client, 413, "request too large")
      return
    end

    local method, path, clen, body_off = parse_http_head(buf)
    if not method then return end                 -- headers not yet complete
    if #buf < body_off + clen - 1 then return end -- body not yet complete

    client:read_stop()
    local body = clen > 0 and buf:sub(body_off, body_off + clen - 1) or ""

    log.debug("signaling: %s %s (%d body bytes)", method, path, #body)

    -- ── GET /relay ── WebSocket relay broker ─────────────────────────────────
    if method == "GET" and path == "/relay" then
      if state.stopped then err_resp(client, 503, "server stopped"); return end
      local buf_lower = buf:lower()
      if not buf_lower:find("upgrade:%s*websocket", 1, false) then
        err_resp(client, 426, "upgrade required")
        return
      end
      local ws_key = buf:match("[Ss]ec%-[Ww]eb[Ss]ocket%-[Kk]ey:%s*([A-Za-z0-9+/=]+)")
      if not ws_key then
        err_resp(client, 400, "missing Sec-WebSocket-Key")
        return
      end
      handle_ws_relay(client, state, ws_key)
      return
    end

    -- ── GET /desc/host ── assign slot, return host desc (long-poll) ──────────
    if method == "GET" and path == "/desc/host" then
      if state.stopped then err_resp(client, 503, "server stopped"); return end

      local slot = random_slot()
      state.slots[slot] = { desc = nil }

      local delivered = false
      local timer

      local function deliver(desc)
        if delivered then return end
        delivered = true
        if timer and not timer:is_closing() then timer:close() end
        if desc then
          ok(client, desc, "X-Slot: " .. slot .. "\r\n")
        else
          state.slots[slot] = nil
          err_resp(client, 408, "timeout waiting for host description")
        end
      end

      if state.host_desc then
        deliver(state.host_desc)
      else
        -- Long-poll: add to waiters list; a timer cancels if host never arrives.
        timer = uv.new_timer()
        timer:start(timeout_ms, 0, function()
          -- remove from waiters before delivering
          for i = #state.host_waiters, 1, -1 do
            if state.host_waiters[i] == deliver then
              table.remove(state.host_waiters, i)
            end
          end
          deliver(nil)
        end)
        state.host_waiters[#state.host_waiters + 1] = deliver
      end
      return
    end

    -- ── PUT /desc/:slot ── guest posts their description ─────────────────────
    local slot = path:match("^/desc/([%x]+)$")
    if method == "PUT" and slot then
      if not state.slots[slot] then
        err_resp(client, 404, "unknown slot: " .. slot)
        return
      end
      if #body == 0 then
        err_resp(client, 400, "empty body")
        return
      end
      state.slots[slot].desc = body
      ok(client, '{"ok":true}')
      -- Notify host callback.
      local cb = state.guest_cb
      if cb then
        schedule(function() cb(slot, body) end)
      end
      return
    end

    -- ── DELETE / ── stop the server ───────────────────────────────────────────
    if method == "DELETE" and (path == "/" or path == "") then
      ok(client, '{"ok":true}')
      schedule(function() state._srv:stop() end)
      return
    end

    err_resp(client, 404, "not found")
  end)
end

-- ── M.new — start a local signaling server ───────────────────────────────────

function M.new(config)
  config = config or {}
  local timeout_ms = config.timeout or DEFAULT_TIMEOUT

  local state = {
    host_desc    = nil,
    host_waiters = {},   -- list of deliver(desc) fns waiting for host_desc
    slots        = {},   -- slot_id → { desc = str | nil }
    guest_cb     = nil,  -- fn(slot, desc_str)
    stopped      = false,
    relay_rooms  = {},   -- token → { a_send_text, a_send_binary, a_client, a_room_ref }
    _srv         = nil,  -- self-reference for DELETE / handler
  }

  local bind_host = config.host or "127.0.0.1"
  local tcp = uv.new_tcp()
  local _, berr = tcp:bind(bind_host, config.port or 0)
  if berr then
    tcp:close()
    return nil, "bind failed: " .. tostring(berr)
  end

  tcp:listen(32, function(lerr)
    if lerr or state.stopped then return end
    local client = uv.new_tcp()
    local ok_accept = pcall(function() tcp:accept(client) end)
    if not ok_accept then
      if not client:is_closing() then client:close() end
      return
    end
    handle_connection(client, state, timeout_ms)
  end)

  local addr = tcp:getsockname()
  local port = addr and addr.port or (config.port or 0)

  local srv = {
    url = "http://" .. bind_host .. ":" .. port,
    _tcp   = tcp,
    _state = state,
  }
  state._srv = srv

  -- Publish the host description; wakes up any long-polling guests.
  function srv:set_host_desc(desc_str)
    state.host_desc = desc_str
    local waiters = state.host_waiters
    state.host_waiters = {}
    for _, deliver in ipairs(waiters) do
      deliver(desc_str)
    end
  end

  -- Register a callback fired for each guest that posts their description.
  -- fn(slot_id, guest_desc_str)
  function srv:on_guest(fn)
    state.guest_cb = fn
  end

  -- Stop the server and reject all pending long-polls.
  function srv:stop()
    if state.stopped then return end
    state.stopped = true
    if not tcp:is_closing() then tcp:close() end
    local waiters = state.host_waiters
    state.host_waiters = {}
    for _, deliver in ipairs(waiters) do deliver(nil) end
    for _, entry in pairs(state.relay_rooms) do
      if entry.a_client and not entry.a_client:is_closing() then
        entry.a_client:close()
      end
    end
    state.relay_rooms = {}
    state.slots       = {}
    state.guest_cb    = nil
  end

  log.debug("signaling server listening on %s", srv.url)
  return srv
end

-- ── HTTP client helpers (guest side) ─────────────────────────────────────────

-- Parse "http[s]://host[:port][/...]" → host, port, secure.
local function parse_url(url)
  local scheme, rest
  if url:sub(1, 8) == "https://" then
    scheme, rest = "https", url:sub(9)
  elseif url:sub(1, 7) == "http://" then
    scheme, rest = "http", url:sub(8)
  else
    return nil, nil, nil, "URL must start with http:// or https://"
  end

  -- Strip any path component — we only need host/port here.
  local authority = rest:match("^([^/]+)") or rest
  local host, port_str = authority:match("^(.+):(%d+)$")
  if not host then
    host     = authority
    port_str = (scheme == "https") and "443" or "80"
  end
  return host, tonumber(port_str), (scheme == "https")
end

-- Low-level: connect (with optional TLS), send request, buffer response.
-- Calls back(err, status_code, x_slot, body).
local function http_req(method, url, path, body, timeout_ms, callback)
  local host, port, secure, perr = parse_url(url)
  if not host then
    schedule(function() callback("invalid URL: " .. tostring(url) .. (perr and (" — " .. perr) or "")) end)
    return
  end

  local done = false
  local tcp  = uv.new_tcp()
  local buf  = ""
  local timer

  local function finish(err, code, slot, resp_body)
    if done then return end
    done = true
    if timer and not timer:is_closing() then timer:close() end
    callback(err, code, slot, resp_body)
  end

  timer = uv.new_timer()
  timer:start(timeout_ms, 0, function()
    if not tcp:is_closing() then tcp:read_stop(); tcp:close() end
    finish("HTTP request timed out after " .. timeout_ms .. " ms")
  end)

  -- Build and send the HTTP request over `io` (plain tcp or TLS adapter).
  local function do_request(io)
    io:read_start(function(rerr, data)
      if done then return end
      if rerr then
        io:close()
        finish("read error: " .. tostring(rerr))
        return
      end
      if not data then
        io:close()
        finish("connection closed before response")
        return
      end

      buf = buf .. data
      local code, slot, clen, body_off = parse_http_response(buf)
      if not code then return end
      if #buf < body_off + clen - 1 then return end

      io:read_stop()
      io:close()
      local resp = clen > 0 and buf:sub(body_off, body_off + clen - 1) or ""
      finish(nil, code, slot, resp)
    end)

    local req_hdrs = method .. " " .. path .. " HTTP/1.1\r\n" .. "Host: " .. host .. "\r\n"
    if body and #body > 0 then
      req_hdrs = req_hdrs .. "Content-Type: application/json\r\n" .. "Content-Length: " .. #body .. "\r\n"
    end
    io:write(req_hdrs .. "\r\n" .. (body or ""))
  end

  uv.getaddrinfo(host, nil, { socktype = "stream" }, function(aerr, res)
    if done then return end
    if aerr or not res or #res == 0 then
      if not tcp:is_closing() then tcp:close() end
      finish("could not resolve '" .. host .. "': " .. tostring(aerr))
      return
    end

    tcp:connect(res[1].addr, port, function(cerr)
      if done then return end
      if cerr then
        tcp:close()
        finish("TCP connect failed: " .. tostring(cerr))
        return
      end

      if secure then
        tls.wrap(tcp, host, function(terr, adapter)
          if done then return end
          if terr then
            finish("TLS error: " .. tostring(terr))
            return
          end
          do_request(adapter)
        end)
      else
        do_request(tcp)
      end
    end)
  end)
end

-- ── M.fetch_host ─────────────────────────────────────────────────────────────

-- Fetch the host description and receive a slot assignment.
-- Long-polls until the host posts their description or timeout fires.
--
-- server_url   — "http://127.0.0.1:PORT" (or the public tunnel URL)
-- timeout_ms   — ms to wait (default: 30000)
-- callback(err, host_desc_str, slot_id)
function M.fetch_host(server_url, timeout_ms, callback)
  if type(timeout_ms) == "function" then
    callback, timeout_ms = timeout_ms, DEFAULT_TIMEOUT
  end
  timeout_ms = timeout_ms or DEFAULT_TIMEOUT

  http_req("GET", server_url, "/desc/host", nil, timeout_ms,
    function(err, code, slot, body)
      if err     then return callback(err) end
      if code ~= 200 then
        return callback("server returned HTTP " .. code .. ": " .. tostring(body))
      end
      if not slot then
        return callback("server did not return X-Slot header")
      end
      callback(nil, body, slot)
    end)
end

-- ── M.post_guest ─────────────────────────────────────────────────────────────

-- Post the guest description to the server.
-- Must be called with the slot_id received from fetch_host.
--
-- server_url   — same URL used in fetch_host
-- slot_id      — the slot string from fetch_host callback
-- desc_str     — guest description JSON string
-- callback(err)
function M.post_guest(server_url, slot_id, desc_str, callback)
  http_req("PUT", server_url, "/desc/" .. slot_id, desc_str, DEFAULT_TIMEOUT,
    function(err, code, _, body)
      if err     then return callback(err) end
      if code ~= 200 then
        return callback("server returned HTTP " .. code .. ": " .. tostring(body))
      end
      callback(nil)
    end)
end

return M
