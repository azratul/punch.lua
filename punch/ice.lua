-- punch/ice.lua
-- Candidate gathering, pairing, prioritization, and selection.
--
-- Implements a minimal ICE-like flow (RFC 8445 subset):
--   - Candidate types: host (local), srflx (STUN reflexive), relay (future)
--   - Priority formula from RFC 8445 §5.1.2 (simplified: single component)
--   - Candidate pairing: cartesian product of local × remote, sorted by priority
--   - Connectivity checks: try pairs in priority order via punch.probe()
--   - Selection: first pair that succeeds wins
--
-- Does NOT implement: full ICE negotiation, role election, aggressive nomination,
-- TCP candidates, DTLS, SDP.
--
-- Works with vim.uv (Neovim) or luv (standalone).
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   -- Gather local candidates (host + srflx) and bind the UDP socket.
--   ice.gather(opts, callback)
--     opts.port  — local UDP port (default: 0 = OS picks)
--     opts.stun  — STUN server "host:port"
--     callback(err, local_candidates, handle)
--       local_candidates — array of candidate tables
--       handle           — the bound udp handle; caller owns it
--
--   -- Build a sorted candidate pair list from local and remote candidates.
--   ice.make_pairs(local_candidates, remote_candidates)
--     returns array of pair tables, highest priority first
--
--   -- Run connectivity checks in priority order; call back with first success.
--   ice.check_pairs(pairs, handle, opts, callback)
--     opts.interval, opts.timeout (per pair)
--     callback(err, winning_pair, handle)
local M = {}

local uv    = (vim and (vim.uv or vim.loop)) or require("luv")
local stun  = require("punch.stun")
local punch = require("punch.punch")

local schedule = function(fn) fn() end

-- ── LAN IP discovery ──────────────────────────────────────────────────────────

-- Return the first non-loopback IPv4 address found on any local interface.
-- Falls back to "127.0.0.1" if nothing useful is found.
--
-- Field name difference: vim.uv uses `address`, standalone luv uses `ip`.
-- We check both.  Prefer addresses in standard private ranges (RFC 1918)
-- over container/bridge IPs on virtual interfaces (veth*, docker*).
local function get_lan_ip()
  local ifaces
  pcall(function() ifaces = uv.interface_addresses() end)
  if not ifaces then return "127.0.0.1" end

  local function is_rfc1918(ip)
    return ip:match("^192%.168%.") or ip:match("^10%.") or ip:match("^172%.1[6-9]%.")
        or ip:match("^172%.2%d%.") or ip:match("^172%.3[01]%.")
  end

  local function is_virtual(name)
    return name:match("^veth") or name:match("^docker") or name:match("^br%-")
  end

  local fallback
  for name, addrs in pairs(ifaces) do
    for _, addr in ipairs(addrs) do
      local ip = addr.ip or addr.address  -- luv uses .ip, vim.uv uses .address
      if ip and (addr.family == "inet" or addr.family == "IPv4") and not addr.internal then
        if is_rfc1918(ip) and not is_virtual(name) then
          return ip  -- best match: physical interface with private range IP
        end
        fallback = fallback or ip  -- keep as fallback if nothing better found
      end
    end
  end

  return fallback or "127.0.0.1"
end

-- ── Candidate priority (RFC 8445 §5.1.2) ─────────────────────────────────────
--
-- priority = 2^24 * type_pref + 2^8 * local_pref + 2^0 * (256 - component)
-- type_pref: host=126, srflx=100, relay=0
-- local_pref: 65535 (single interface/single component)
-- component: 1

local TYPE_PREF = { host = 126, srflx = 100, relay = 0 }
local LOCAL_PREF = 65535
local COMPONENT  = 1

local function candidate_priority(ctype)
  local tp = TYPE_PREF[ctype] or 0
  return tp * 16777216 + LOCAL_PREF * 256 + (256 - COMPONENT)
end

-- ── Candidate pair priority (RFC 8445 §6.1.2.3) ──────────────────────────────
--
-- pair_priority = 2^32 * min(G, D) + 2 * max(G, D) + tie_break
-- G = controlling candidate priority, D = controlled.
-- We don't fully implement roles; treat local as controlling.

local function pair_priority(local_prio, remote_prio)
  local g, d = local_prio, remote_prio
  local mn = math.min(g, d)
  local mx = math.max(g, d)
  local tie = (g > d) and 1 or 0
  -- Avoid integer overflow in Lua doubles: 2^32 * mn fits if mn < 2^21
  -- In practice our priorities fit in 28 bits so this is safe.
  return mn * 4294967296 + mx * 2 + tie
end

-- ── Public API ────────────────────────────────────────────────────────────────

-- Gather local candidates by binding a UDP socket and querying STUN.
--
-- callback(err, candidates, handle)
function M.gather(opts, callback)
  opts = opts or {}

  local handle = uv.new_udp()
  local _, bind_err = handle:bind("0.0.0.0", opts.port or 0)
  if bind_err then
    handle:close()
    schedule(function()
      callback("UDP bind failed: " .. tostring(bind_err))
    end)
    return
  end

  local sockname   = handle:getsockname()
  local local_port = sockname and sockname.port or 0

  -- Host candidate: local LAN address (useful for same-subnet peers).
  local host_cand = {
    type     = "host",
    addr     = get_lan_ip(),
    port     = local_port,
    priority = candidate_priority("host"),
  }

  if not opts.stun or opts.stun == "" or opts.stun == false then
    schedule(function() callback(nil, { host_cand }, handle) end)
    return
  end

  -- Srflx candidate: public address via STUN (works for non-symmetric NAT).
  stun.discover({ server = opts.stun, handle = handle }, function(serr, addr, port)
    if serr then
      -- STUN failed: return only the host candidate; direct LAN or relay may work.
      callback(nil, { host_cand }, handle)
      return
    end

    local srflx_cand = {
      type     = "srflx",
      addr     = addr,
      port     = port,
      priority = candidate_priority("srflx"),
    }

    -- srflx first (higher priority); host second
    callback(nil, { srflx_cand, host_cand }, handle)
  end)
end

-- Build candidate pairs from local and remote candidates, sorted by priority.
--
-- Pairs with type mismatches that cannot succeed are excluded:
--   - relay × relay not paired (both would need to hit the same relay)
--   - host  × srflx or srflx × host: included — useful for LAN or one-sided NAT
function M.make_pairs(local_cands, remote_cands)
  local pairs = {}

  for _, lc in ipairs(local_cands) do
    for _, rc in ipairs(remote_cands) do
      -- Skip relay-to-relay (relay module handles that separately).
      if not (lc.type == "relay" and rc.type == "relay") then
        local lprio = lc.priority or candidate_priority(lc.type)
        local rprio = rc.priority or candidate_priority(rc.type)
        
        pairs[#pairs+1] = {
          local_cand  = lc,
          remote_cand = rc,
          priority    = pair_priority(lprio, rprio),
          state       = "waiting",  -- waiting | in_progress | succeeded | failed
        }
      end
    end
  end

  table.sort(pairs, function(a, b) return a.priority > b.priority end)
  return pairs
end

-- Run connectivity checks in priority order.
-- Tries each pair sequentially; calls back with the first one that succeeds.
-- If all pairs fail, calls back with an error.
--
-- callback(err, winning_pair, handle)
function M.check_pairs(pairs, handle, opts, callback)
  opts = opts or {}
  local i    = 0
  local done = false

  local function try_next()
    if done then return end
    i = i + 1
    if i > #pairs then
      done = true
      callback("all " .. #pairs .. " candidate pairs failed")
      return
    end

    local pair = pairs[i]
    pair.state = "in_progress"

    punch.probe(handle, pair.remote_cand.addr, pair.remote_cand.port, opts,
      function(err, h)
        if done then return end
        if err then
          pair.state = "failed"
          try_next()
        else
          done = true
          pair.state = "succeeded"
          callback(nil, pair, h)
        end
      end)
  end

  if #pairs == 0 then
    schedule(function() callback("no candidate pairs to check") end)
    return
  end

  try_next()
end

return M
