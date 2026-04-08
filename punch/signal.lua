-- punch/signal.lua
-- Description encoding/decoding for out-of-band signaling.
--
-- A "description" is everything one peer needs to publish for the other to
-- connect.  It is serialized to a JSON string that can travel over any
-- out-of-band channel: URL fragment, clipboard, chat, QR code.
--
-- No server is required.  If server-based signaling is needed in the future,
-- register a backend via signal.set_backend(backend).
--
-- ── Description schema ────────────────────────────────────────────────────────
--
--   {
--     v          = 1,             -- protocol version
--     token      = "hex16chars",  -- random session identifier
--     pub        = "base64(32b)", -- X25519 ECDH public key (optional; enables ECDH)
--     candidates = {
--       { t = "host",  a = "192.168.1.5",   p = 54321 },
--       { t = "srflx", a = "203.0.113.5",   p = 54321 },
--       { t = "relay", a = "relay.host.com", p = 443, rt = "relay_token" },
--     },
--   }
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   signal.encode(desc)           → string | nil, err
--   signal.decode(str)            → desc   | nil, err
--   signal.set_backend(backend)   — register a remote signaling backend
--   signal.publish(desc, cb)      — publish via backend (cb(err, str))
--   signal.fetch(token, cb)       — fetch via backend  (cb(err, desc))
local M = {}

local VERSION = 1

-- ── JSON ──────────────────────────────────────────────────────────────────────
-- Prefer vim.json (Neovim) or cjson (standalone LuaJIT).  Both are fast and
-- correct.  A minimal pure-Lua fallback handles the subset we actually use.

local _encode, _decode

local function load_json()
  if _encode then return true end

  if vim and vim.json then
    _encode = vim.json.encode
    _decode = vim.json.decode
    return true
  end

  local ok, lib = pcall(require, "cjson")
  if ok then
    _encode = lib.encode
    _decode = lib.decode
    return true
  end

  -- Minimal fallback: handles the specific types in our description.
  local function enc(v)
    local t = type(v)
    if t == "nil"     then return "null" end
    if t == "boolean" then return tostring(v) end
    if t == "number"  then return tostring(math.floor(v) == v and math.floor(v) or v) end
    if t == "string"  then
      return '"' .. v:gsub('\\','\\\\'):gsub('"','\\"')
                     :gsub('\n','\\n'):gsub('\r','\\r'):gsub('\t','\\t') .. '"'
    end
    if t == "table" then
      -- Array detection: all keys are 1..#t
      if #v > 0 then
        local parts = {}
        for i = 1, #v do parts[i] = enc(v[i]) end
        return "[" .. table.concat(parts, ",") .. "]"
      end
      local parts = {}
      for k, val in pairs(v) do
        parts[#parts+1] = '"' .. tostring(k) .. '":' .. enc(val)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
    error("signal: cannot encode value of type " .. t)
  end
  _encode = enc

  -- Minimal recursive-descent JSON decoder for our schema.
  local function dec(s, i)
    i = i or 1
    -- skip whitespace
    i = s:match("^%s*()", i)
    local c = s:sub(i, i)

    if c == '"' then
      local j = i + 1
      local out = {}
      while j <= #s do
        local ch = s:sub(j, j)
        if ch == '"' then break end
        if ch == '\\' then
          local esc = s:sub(j+1, j+1)
          if     esc == '"'  then out[#out+1] = '"';  j = j + 2
          elseif esc == '\\' then out[#out+1] = '\\'; j = j + 2
          elseif esc == 'n'  then out[#out+1] = '\n'; j = j + 2
          elseif esc == 'r'  then out[#out+1] = '\r'; j = j + 2
          elseif esc == 't'  then out[#out+1] = '\t'; j = j + 2
          else out[#out+1] = esc; j = j + 2 end
        else
          out[#out+1] = ch; j = j + 1
        end
      end
      return table.concat(out), j + 1

    elseif c == '{' then
      local t, j = {}, i + 1
      j = s:match("^%s*()", j)
      if s:sub(j,j) == '}' then return t, j+1 end
      while true do
        local k; k, j = dec(s, j)
        j = s:match("^%s*:%s*()", j)
        local v; v, j = dec(s, j)
        t[k] = v
        j = s:match("^%s*()", j)
        if s:sub(j,j) == '}' then return t, j+1 end
        j = s:match("^,%s*()", j)
      end

    elseif c == '[' then
      local t, j = {}, i + 1
      j = s:match("^%s*()", j)
      if s:sub(j,j) == ']' then return t, j+1 end
      while true do
        local v; v, j = dec(s, j)
        t[#t+1] = v
        j = s:match("^%s*()", j)
        if s:sub(j,j) == ']' then return t, j+1 end
        j = s:match("^,%s*()", j)
      end

    elseif s:sub(i, i+3) == "null"  then return nil,   i + 4
    elseif s:sub(i, i+3) == "true"  then return true,  i + 4
    elseif s:sub(i, i+4) == "false" then return false, i + 5

    else
      local num, j = s:match("^(-?%d+%.?%d*[eE]?[+-]?%d*)()", i)
      if num then return tonumber(num), j end
      error("signal: unexpected character '" .. c .. "' at position " .. i)
    end
  end

  _decode = function(s)
    local ok2, result = pcall(dec, s)
    if not ok2 then error(result) end
    return result
  end

  return true
end

-- ── Encode / Decode ───────────────────────────────────────────────────────────

-- Serialize a description table to a string.
-- Returns: string | nil, err
function M.encode(desc)
  if type(desc) ~= "table" then
    return nil, "description must be a table"
  end
  if not desc.candidates or #desc.candidates == 0 then
    return nil, "description must have at least one candidate"
  end

  load_json()
  local wire = {
    v          = VERSION,
    token      = desc.token or "",
    candidates = (function()
      local out = {}
      for _, c in ipairs(desc.candidates) do
        local entry = { t = c.type, a = c.addr or "127.0.0.1", p = c.port }
        if c.relay_token then entry.rt = c.relay_token end
        out[#out+1] = entry
      end
      return out
    end)(),
  }
  if desc.pub then wire.pub = desc.pub end  -- X25519 public key (base64, optional)
  local ok, result = pcall(_encode, wire)
  if not ok then return nil, tostring(result) end
  return result
end

-- Parse a description string.
-- Returns: desc | nil, err
function M.decode(str)
  if type(str) ~= "string" or str == "" then
    return nil, "description string is empty or not a string"
  end

  load_json()
  local ok, raw = pcall(_decode, str)
  if not ok then return nil, "JSON parse error: " .. tostring(raw) end
  if type(raw) ~= "table" then return nil, "description is not a JSON object" end

  if raw.v ~= VERSION then
    return nil, "unsupported description version: " .. tostring(raw.v)
  end
  if type(raw.candidates) ~= "table" or #raw.candidates == 0 then
    return nil, "description has no candidates"
  end

  local candidates = {}
  for _, c in ipairs(raw.candidates) do
    if type(c.t) ~= "string" or type(c.a) ~= "string" or type(c.p) ~= "number" then
      return nil, "malformed candidate entry"
    end
    local entry = { type = c.t, addr = c.a, port = math.floor(c.p) }
    if c.rt then entry.relay_token = c.rt end
    candidates[#candidates+1] = entry
  end

  return {
    version    = raw.v,
    token      = raw.token or "",
    pub        = (type(raw.pub) == "string" and raw.pub ~= "") and raw.pub or nil,
    candidates = candidates,
  }
end

-- ── Server-based signaling backend (optional) ─────────────────────────────────
-- A backend must implement:
--   backend.publish(desc, callback)   — callback(err, token)
--   backend.fetch(token, callback)    — callback(err, desc)
--
-- When no backend is set, signaling is purely out-of-band.

local _backend = nil

function M.set_backend(backend)
  _backend = backend
end

function M.publish(desc, callback)
  if not _backend then
    callback("no signaling backend configured — exchange the description string manually")
    return
  end
  _backend.publish(desc, callback)
end

function M.fetch(token, callback)
  if not _backend then
    callback("no signaling backend configured — exchange the description string manually")
    return
  end
  _backend.fetch(token, callback)
end

return M
