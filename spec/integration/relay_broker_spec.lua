-- spec/integration/relay_broker_spec.lua
-- Integration tests for the WebSocket relay broker endpoint in signaling_server.lua.
--
-- Tests exercise the /relay endpoint via relay.connect() (the real client), using
-- the same event-loop discipline as signaling_server_spec.lua: every uv handle
-- must be closed before uv.run() can drain.

local uv    = require("luv")
local sig   = require("punch.signaling_server")
local relay = require("punch.relay")

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

local function broker_url(srv)
  return srv.url:gsub("^http://", "ws://") .. "/relay"
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("relay broker (/relay endpoint)", function()

  it("pairs two peers with the same token and sends ready to both", function()
    local ready_a, ready_b = false, false

    local ok = run_loop(3000, function(cancel)
      local srv = sig.new({ port = 0 })
      local url  = broker_url(srv)
      local tok  = relay.make_token()
      local done = 0

      local function check()
        done = done + 1
        if done == 2 then srv:stop(); cancel() end
      end

      relay.connect(url, tok, { timeout = 2000 }, function(err, conn)
        assert.is_nil(err, "peer A relay error: " .. tostring(err))
        ready_a = (conn ~= nil)
        if conn then conn:close() end
        check()
      end)

      relay.connect(url, tok, { timeout = 2000 }, function(err, conn)
        assert.is_nil(err, "peer B relay error: " .. tostring(err))
        ready_b = (conn ~= nil)
        if conn then conn:close() end
        check()
      end)
    end)

    assert.is_true(ok,      "test timed out")
    assert.is_true(ready_a, "peer A did not receive ready")
    assert.is_true(ready_b, "peer B did not receive ready")
  end)

  it("forwards binary frames between paired peers", function()
    local received_by_b, received_by_a

    local ok = run_loop(3000, function(cancel)
      local srv = sig.new({ port = 0 })
      local url  = broker_url(srv)
      local tok  = relay.make_token()
      local done = 0

      local function check()
        done = done + 1
        if done == 2 then srv:stop(); cancel() end
      end

      relay.connect(url, tok, { timeout = 2000 }, function(err, conn_a)
        assert.is_nil(err)
        conn_a:on("data", function(data)
          received_by_a = data
          conn_a:close()
          check()
        end)
        conn_a:send("hello from A")
      end)

      relay.connect(url, tok, { timeout = 2000 }, function(err, conn_b)
        assert.is_nil(err)
        conn_b:on("data", function(data)
          received_by_b = data
          conn_b:send("hello from B")
          conn_b:close()
          check()
        end)
      end)
    end)

    assert.is_true(ok, "test timed out")
    assert.equal("hello from A", received_by_b)
    assert.equal("hello from B", received_by_a)
  end)

  it("two token pairs on the same server do not cross-contaminate", function()
    local recv = { aa = nil, bb = nil }

    local ok = run_loop(3000, function(cancel)
      local srv   = sig.new({ port = 0 })
      local url   = broker_url(srv)
      local tok1  = relay.make_token()
      local tok2  = relay.make_token()
      local done  = 0

      local function check()
        done = done + 1
        if done == 2 then srv:stop(); cancel() end
      end

      -- Pair 1
      relay.connect(url, tok1, { timeout = 2000 }, function(err, c1a)
        assert.is_nil(err)
        c1a:on("data", function(data) recv.aa = data; c1a:close(); check() end)
      end)
      relay.connect(url, tok1, { timeout = 2000 }, function(err, c1b)
        assert.is_nil(err)
        c1b:send("msg-1"); c1b:close()
      end)

      -- Pair 2
      relay.connect(url, tok2, { timeout = 2000 }, function(err, c2a)
        assert.is_nil(err)
        c2a:on("data", function(data) recv.bb = data; c2a:close(); check() end)
      end)
      relay.connect(url, tok2, { timeout = 2000 }, function(err, c2b)
        assert.is_nil(err)
        c2b:send("msg-2"); c2b:close()
      end)
    end)

    assert.is_true(ok, "test timed out")
    assert.equal("msg-1", recv.aa)
    assert.equal("msg-2", recv.bb)
  end)

  it("times out when only one peer connects", function()
    local result

    local ok = run_loop(3000, function(cancel)
      local srv = sig.new({ port = 0 })
      local url  = broker_url(srv)
      local tok  = relay.make_token()

      relay.connect(url, tok, { timeout = 400 }, function(err, conn)
        result = { err = err, conn = conn }
        srv:stop()
        cancel()
      end)
      -- Second peer never connects.
    end)

    assert.is_true(ok, "test timed out")
    assert.is_string(result.err, "expected a timeout error")
    assert.is_nil(result.conn)
  end)

  it("cleans up the waiting room when the first peer disconnects before pairing", function()
    -- Peer A connects but times out (no partner).  After cleanup, a fresh pair
    -- using the same token must succeed.
    local second_pair_ready = false

    local ok = run_loop(6000, function(cancel)
      local srv  = sig.new({ port = 0 })
      local url  = broker_url(srv)
      local tok  = relay.make_token()

      -- Peer A connects; no second peer → times out after 500 ms.
      relay.connect(url, tok, { timeout = 500 }, function(err, conn)
        if conn then conn:close() end
        -- After A's stale entry is cleaned up, start a fresh pair concurrently.
        local t = uv.new_timer()
        t:start(200, 0, function()
          t:close()
          local results = {}
          local function check()
            if results.c1 ~= nil and results.c2 ~= nil then
              second_pair_ready = (results.c1 ~= false and results.c2 ~= false)
              if results.c1 and results.c1 ~= false then results.c1:close() end
              if results.c2 and results.c2 ~= false then results.c2:close() end
              srv:stop(); cancel()
            end
          end
          -- Both peers start concurrently.
          relay.connect(url, tok, { timeout = 2000 }, function(e1, c1)
            assert.is_nil(e1, "fresh peer 1 error: " .. tostring(e1))
            results.c1 = c1 or false; check()
          end)
          relay.connect(url, tok, { timeout = 2000 }, function(e2, c2)
            assert.is_nil(e2, "fresh peer 2 error: " .. tostring(e2))
            results.c2 = c2 or false; check()
          end)
        end)
      end)
    end)

    assert.is_true(ok,                "test timed out")
    assert.is_true(second_pair_ready, "second pair did not become ready after cleanup")
  end)

end)
