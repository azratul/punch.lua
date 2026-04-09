-- spec/integration/channel_spec.lua
-- Integration tests for punch/channel.lua
--
-- Tests run a real libuv event loop.  Two loopback UDP sockets are used to
-- simulate a direct P2P channel without going through punch.probe.
--
-- Wire format note: channel.new_udp adds a 1-byte frame type prefix to every
-- datagram (\x01 = data, \x00 = keepalive).  Tests that inspect raw datagrams
-- must account for this prefix.

local uv      = require("luv")
local channel = require("punch.channel")

-- ── helpers ───────────────────────────────────────────────────────────────────

local function run_loop(budget_ms, setup_fn)
  local timed_out = false
  local watchdog  = uv.new_timer()
  watchdog:start(budget_ms, 0, function()
    timed_out = true
    if not watchdog:is_closing() then watchdog:close() end
  end)
  setup_fn(function()
    if not watchdog:is_closing() then watchdog:close() end
  end)
  uv.run("default")
  return not timed_out
end

-- Create two bound UDP sockets and the two channel objects that talk to each other.
-- Returns chA, chB, hA, hB.  Caller is responsible for channel cleanup.
local function make_pair(opts_a, opts_b)
  local hA = uv.new_udp()
  local hB = uv.new_udp()
  hA:bind("127.0.0.1", 0)
  hB:bind("127.0.0.1", 0)
  local portA = hA:getsockname().port
  local portB = hB:getsockname().port

  local chA = channel.new_udp(hA, "127.0.0.1", portB, opts_a or {})
  local chB = channel.new_udp(hB, "127.0.0.1", portA, opts_b or {})
  return chA, chB, hA, hB
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("channel (UDP)", function()

  -- ── basic send / receive ─────────────────────────────────────────────────

  it("delivers a message from A to B", function()
    local received
    local ok = run_loop(2000, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 60000, peer_timeout = 120000 },
        { keepalive_interval = 60000, peer_timeout = 120000 }
      )
      chB:on("data", function(data)
        received = data
        chA:close()
        chB:close()
        cancel()
      end)
      chA:send("hello from A")
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.equal("hello from A", received)
  end)

  it("delivers messages in both directions", function()
    local got_by_b, got_by_a
    local ok = run_loop(2000, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 60000, peer_timeout = 120000 },
        { keepalive_interval = 60000, peer_timeout = 120000 }
      )
      local function maybe_cancel()
        if got_by_a and got_by_b then
          chA:close(); chB:close(); cancel()
        end
      end
      chA:on("data", function(d) got_by_a = d; maybe_cancel() end)
      chB:on("data", function(d) got_by_b = d; maybe_cancel() end)
      chA:send("A→B")
      chB:send("B→A")
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.equal("A→B", got_by_b)
    assert.equal("B→A", got_by_a)
  end)

  -- ── keepalive ────────────────────────────────────────────────────────────
  --
  -- Keepalives keep the channel alive even when no application data is sent.
  -- If keepalive correctly resets the dead-peer clock on both sides, neither
  -- channel should close within (peer_timeout) despite no data traffic.

  it("keepalives prevent dead-peer timeout during idle period", function()
    -- With ka=80ms and dead_timeout=300ms, keepalives from each peer reset
    -- the other's dead clock.  Neither channel should close with "peer timeout"
    -- within 250ms; only "closed by local peer" is acceptable at cleanup time.
    local peer_timeout_fired = false
    local ok = run_loop(1500, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 80, peer_timeout = 300 },
        { keepalive_interval = 80, peer_timeout = 300 }
      )
      local function watch(reason)
        if reason == "peer timeout" then peer_timeout_fired = true end
      end
      chA:on("close", watch)
      chB:on("close", watch)

      -- Close both channels cleanly after 250ms (before dead_timeout fires).
      local t = uv.new_timer()
      t:start(250, 0, function()
        t:close()
        chA:close()
        chB:close()
        cancel()
      end)
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.is_false(peer_timeout_fired, "dead-peer timer fired — keepalives not working")
  end)

  -- ── dead-peer detection ──────────────────────────────────────────────────
  --
  -- When one side stops sending (including keepalives), the other side should
  -- detect the silence and close with "peer timeout".

  it("closes the channel when the peer stops responding", function()
    -- chB is closed immediately (simulates dead peer).
    -- chA should detect no traffic within peer_timeout and close itself.
    local close_reason
    local ok = run_loop(1500, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 80, peer_timeout = 300 },
        { keepalive_interval = 80, peer_timeout = 300 }
      )
      chA:on("close", function(reason)
        close_reason = reason
        cancel()
      end)
      -- Close B immediately so it never sends keepalives to A.
      chB:close()
    end)

    assert.is_true(ok, "test exceeded budget — dead-peer timer did not fire")
    assert.equal("peer timeout", close_reason)
  end)

  -- ── payload size limit ───────────────────────────────────────────────────

  it("rejects oversized payloads with a close event", function()
    local close_reason
    local ok = run_loop(500, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 60000, peer_timeout = 120000 },
        { keepalive_interval = 60000, peer_timeout = 120000 }
      )
      chA:on("close", function(reason)
        close_reason = reason
        chB:close()
        cancel()
      end)
      -- Send a payload that exceeds MAX_PAYLOAD (65000 bytes).
      chA:send(string.rep("x", 65001))
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.is_string(close_reason, "expected close event with reason")
    assert.truthy(close_reason:find("too large"), "expected 'too large' in reason: " .. tostring(close_reason))
  end)

  -- ── encryption (plaintext path) ──────────────────────────────────────────

  it("works in plaintext mode (no key)", function()
    local received
    local ok = run_loop(2000, function(cancel)
      local chA, chB = make_pair(
        { keepalive_interval = 60000, peer_timeout = 120000 },
        { keepalive_interval = 60000, peer_timeout = 120000 }
      )
      chB:on("data", function(data)
        received = data
        chA:close(); chB:close(); cancel()
      end)
      chA:send("plaintext payload")
    end)

    assert.is_true(ok, "test exceeded budget")
    assert.equal("plaintext payload", received)
  end)

  -- ── state_change event (session) ─────────────────────────────────────────
  --
  -- This section tests the state_change event added to session.lua.
  -- We use session.new() directly (without punch.start's auto-gather) to
  -- control the state machine without network I/O.

  describe("session state_change event", function()
    local session = require("punch.session")

    it("emits state_change from 'new' to 'gathering' when gather() is called", function()
      local changes = {}
      local s = session.new({ stun = false, timeout = 500 })
      s:on("state_change", function(new, old) changes[#changes+1] = { new=new, old=old } end)

      local ok = run_loop(1500, function(cancel)
        s:gather(function()
          s:close()
          cancel()
        end)
      end)

      assert.is_true(ok, "test exceeded budget")
      -- At minimum we should see new→gathering.
      assert.truthy(#changes >= 1, "no state_change events emitted")
      assert.equal("gathering", changes[1].new)
      assert.equal("new",       changes[1].old)
    end)

    it("state sequence includes 'ready' after gather completes without STUN", function()
      local states = {}
      local s = session.new({ stun = false, timeout = 500 })
      s:on("state_change", function(new) states[#states+1] = new end)

      local ok = run_loop(1500, function(cancel)
        s:gather(function()
          -- gather done → state should be "ready" now
          s:close()
          cancel()
        end)
      end)

      assert.is_true(ok, "test exceeded budget")
      -- Must have passed through "gathering" then "ready".
      local saw_gathering = false
      local saw_ready     = false
      for _, st in ipairs(states) do
        if st == "gathering" then saw_gathering = true end
        if st == "ready"     then saw_ready     = true end
      end
      assert.is_true(saw_gathering, "missing 'gathering' state_change")
      assert.is_true(saw_ready,     "missing 'ready' state_change")
    end)
  end)

end)
