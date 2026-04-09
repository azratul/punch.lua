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
local log      = require("punch.log")
local tls      = require("punch.tls")
local schedule = (vim and vim.schedule) or function(fn) fn() end

local DEFAULT_TIMEOUT = 30000
local MAX_REQUEST     = 65536   -- hard cap: descriptions are ~500 bytes

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
    state.slots     = {}
    state.guest_cb  = nil
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
