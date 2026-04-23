-- spec/integration/punch_loopback_spec.lua
-- Integration tests for punch.probe() using two UDP sockets on loopback.
--
-- These tests drive a real libuv event loop (uv.run).  They are separated
-- into spec/integration/ so they can be run independently from the pure unit
-- tests when a network interface is required.
--
-- Design constraint:
--   punch.probe() does NOT close or recv_stop the handle on completion — the
--   caller owns it.  More importantly, punch.probe() creates internal interval
--   and timeout timers that are only closed when that probe's own finish()
--   fires.  Closing the handle early (before finish fires) leaves the timers
--   alive and stalls uv.run.
--
--   Rule: never close a handle until its probe callback has fired.
--
-- A watchdog timer provides a hard wall-clock budget per test.  When it fires
-- it force-closes every registered handle; the probe timers will timeout and
-- drain the loop on their own within their configured timeout window.

local uv    = require("luv")
local punch = require("punch.punch")

-- ── helpers ───────────────────────────────────────────────────────────────────

-- Safely close a UDP handle (idempotent).
local function safe_close(h)
  if not h or h:is_closing() then return end
  pcall(function() h:recv_stop() end)
  h:close()
end

-- Run setup_fn(cancel_watchdog) inside a fresh event-loop call.
-- cancel_watchdog() should be called once all work is finished so the loop can
-- drain without waiting for the watchdog.
-- Returns: true when the loop drained before budget_ms, false on watchdog fire.
local function run_loop(budget_ms, setup_fn)
  local timed_out = false

  local watchdog = uv.new_timer()
  watchdog:start(budget_ms, 0, function()
    timed_out = true
    if not watchdog:is_closing() then watchdog:close() end
    -- Do NOT force-close probe handles here: the timers inside punch.probe are
    -- separate uv_timer_t objects and will drain the loop on their own when
    -- they fire.  Trying to close the UDP handles early can cause send errors
    -- inside the timer callbacks that prevent normal timer cleanup.
  end)

  setup_fn(function()  -- cancel_watchdog
    if not watchdog:is_closing() then watchdog:close() end
  end)

  uv.run("default")
  return not timed_out
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("punch loopback", function()

  -- ── two-peer loopback ─────────────────────────────────────────────────────

  it("two peers punch through to each other on loopback", function()
    local resultA, resultB

    local ok = run_loop(3000, function(cancel)
      local hA = uv.new_udp()
      local hB = uv.new_udp()
      assert(hA:bind("127.0.0.1", 0))
      assert(hB:bind("127.0.0.1", 0))

      local portA = hA:getsockname().port
      local portB = hB:getsockname().port

      local function maybe_cancel()
        if resultA ~= nil and resultB ~= nil then cancel() end
      end

      punch.probe(hA, "127.0.0.1", portB, { interval = 50, timeout = 2000 },
        function(err)
          resultA = err or "ok"
          safe_close(hA)
          maybe_cancel()
        end)

      punch.probe(hB, "127.0.0.1", portA, { interval = 50, timeout = 2000 },
        function(err)
          resultB = err or "ok"
          safe_close(hB)
          maybe_cancel()
        end)
    end)

    assert.is_true(ok,       "test exceeded budget (3 s) — event loop did not drain")
    assert.equal("ok", resultA, "peer A probe failed: " .. tostring(resultA))
    assert.equal("ok", resultB, "peer B probe failed: " .. tostring(resultB))
  end)

  -- ── timeout when remote is unreachable ────────────────────────────────────

  -- Port 1/UDP is reserved and will not have a listener.  The probe must time
  -- out and call the callback with an error string.
  -- probe timeout = 500 ms so this test completes in ~500 ms.

  it("probe fails with an error when the remote does not respond", function()
    local result

    local ok = run_loop(2000, function(cancel)
      local h = uv.new_udp()
      assert(h:bind("127.0.0.1", 0))

      punch.probe(h, "127.0.0.1", 1, { interval = 100, timeout = 500 },
        function(err, handle)
          result = { err = err, handle = handle }
          safe_close(h)
          cancel()
        end)
    end)

    assert.is_true(ok,           "test exceeded budget (2 s)")
    assert.is_not_nil(result,    "callback was never invoked")
    assert.is_string(result.err, "expected a timeout error string, got: " .. tostring(result and result.err))
    assert.is_nil(result.handle, "handle should be nil on failure")
  end)

  -- ── multiple concurrent pairs ─────────────────────────────────────────────

  -- Three independent A↔B loopback pairs run simultaneously in the same event
  -- loop.  All six probes must succeed without interfering with each other.

  it("multiple independent pairs run concurrently without interference", function()
    local PAIRS   = 3
    local results = {}
    local pending = PAIRS * 2

    local ok = run_loop(4000, function(cancel)
      local function on_done(id, err)
        results[id] = err or "ok"
        pending = pending - 1
        if pending == 0 then cancel() end
      end

      for i = 1, PAIRS do
        local hA = uv.new_udp()
        local hB = uv.new_udp()
        assert(hA:bind("127.0.0.1", 0))
        assert(hB:bind("127.0.0.1", 0))

        local portA = hA:getsockname().port
        local portB = hB:getsockname().port

        punch.probe(hA, "127.0.0.1", portB, { interval = 50, timeout = 2000 },
          function(err)
            safe_close(hA)
            on_done("A" .. i, err)
          end)

        punch.probe(hB, "127.0.0.1", portA, { interval = 50, timeout = 2000 },
          function(err)
            safe_close(hB)
            on_done("B" .. i, err)
          end)
      end
    end)

    assert.is_true(ok, "test exceeded budget (4 s)")
    for i = 1, PAIRS do
      local aid, bid = "A" .. i, "B" .. i
      assert.equal("ok", results[aid], "pair " .. i .. " peer A failed: " .. tostring(results[aid]))
      assert.equal("ok", results[bid], "pair " .. i .. " peer B failed: " .. tostring(results[bid]))
    end
  end)

  -- ── Peer-reflexive learning (TXID matching) ───────────────────────────────

  it("accepts STUN response from a different port if TXID matches (peer-reflexive)", function()
    local result_addr, result_port, portC

    local ok = run_loop(2000, function(cancel)
      local hA = uv.new_udp()
      local hB = uv.new_udp() -- The "legit" remote we are probing
      local hC = uv.new_udp() -- The "surprise" remote that sends the response
      
      assert(hA:bind("127.0.0.1", 0))
      assert(hB:bind("127.0.0.1", 0))
      assert(hC:bind("127.0.0.1", 0))

      local portA = hA:getsockname().port
      local portB = hB:getsockname().port
      portC = hC:getsockname().port

      hB:recv_start(function(err, data, addr)
        if data and #data >= 20 then
          local txid = data:sub(9, 20)
          
          -- Build a STUN response manually
          local stun = require("punch.stun")
          local bit = require("bit")
          local pack16 = stun._pack16
          local pack32 = stun._pack32
          local MAGIC = stun._MAGIC
          local MAGIC_HI = stun._MAGIC_HI
          
          local ip = addr.address or addr.ip
          local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
          local ip32 = tonumber(a)*16777216 + tonumber(b)*65536 + tonumber(c)*256 + tonumber(d)
          local xport = bit.bxor(portA, MAGIC_HI)
          local xaddr = bit.bxor(ip32, MAGIC)
          local attr = pack16(0x0020) .. pack16(8) .. "\x00\x01" .. pack16(xport) .. pack32(xaddr)
          local resp = pack16(0x0101) .. pack16(#attr) .. pack32(MAGIC) .. txid .. attr
          
          -- Send from hC (different port!)
          hC:send(resp, "127.0.0.1", portA, function() end)
        end
      end)

      punch.probe(hA, "127.0.0.1", portB, { interval = 50, timeout = 1000 },
        function(err, handle, learned_addr, learned_port)
          result_addr = learned_addr
          result_port = learned_port
          safe_close(hA)
          safe_close(hB)
          safe_close(hC)
          cancel()
        end)
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.equal("127.0.0.1", result_addr)
    assert.equal(portC, result_port, "should have learned the port of the socket that actually sent the response")
  end)

end)
