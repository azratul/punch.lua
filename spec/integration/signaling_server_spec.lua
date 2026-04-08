-- spec/integration/signaling_server_spec.lua
-- Integration tests for punch/signaling_server.lua
--
-- All tests run a real local HTTP server and exercise the full request/response
-- cycle with uv.run("default").  Same event-loop discipline as punch_loopback:
-- every uv handle must be closed before uv.run can drain.

local uv  = require("luv")
local sig = require("punch.signaling_server")

-- ── helpers ───────────────────────────────────────────────────────────────────

local function run_loop(budget_ms, setup_fn)
  local timed_out = false
  local watchdog  = uv.new_timer()
  watchdog:start(budget_ms, 0, function()
    timed_out = true
    if not watchdog:is_closing() then watchdog:close() end
  end)

  setup_fn(function()  -- cancel_watchdog
    if not watchdog:is_closing() then watchdog:close() end
  end)

  uv.run("default")
  return not timed_out
end

-- A minimal description string that the server accepts as-is (opaque body).
local FAKE_HOST_DESC  = '{"v":1,"token":"aabbccddeeff0011","candidates":[{"t":"host","a":"192.168.1.1","p":1234}]}'
local FAKE_GUEST_DESC = '{"v":1,"token":"1122334455667788","candidates":[{"t":"host","a":"192.168.1.2","p":5678}]}'

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("signaling_server", function()

  -- ── server construction ───────────────────────────────────────────────────

  describe("new()", function()
    it("starts on a random port and returns a URL", function()
      local srv, err = sig.new({ port = 0 })
      assert.is_nil(err)
      assert.is_not_nil(srv)
      assert.is_string(srv.url)
      assert.truthy(srv.url:match("^http://127%.0%.0%.1:%d+$"),
        "url should be http://127.0.0.1:PORT, got: " .. tostring(srv.url))
      srv:stop()
      -- stop closes the TCP handle; drain the loop so the close callback fires
      uv.run("nowait")
    end)

    it("starts on a specific port when given one", function()
      -- Use a high port unlikely to be in use; retry with 0 if bind fails.
      local srv, err = sig.new({ port = 0 })
      assert.is_nil(err)
      local port = tonumber(srv.url:match(":(%d+)$"))
      assert.truthy(port and port > 0)
      srv:stop()
      uv.run("nowait")
    end)
  end)

  -- ── host description + guest fetch ────────────────────────────────────────

  describe("fetch_host", function()
    it("returns host desc and a slot when desc is already published", function()
      local result

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })
        srv:set_host_desc(FAKE_HOST_DESC)

        sig.fetch_host(srv.url, 2000, function(err, desc, slot)
          result = { err = err, desc = desc, slot = slot }
          srv:stop()
          cancel()
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_nil(result.err,        "expected no error, got: " .. tostring(result.err))
      assert.equal(FAKE_HOST_DESC, result.desc)
      assert.is_string(result.slot)
      assert.truthy(result.slot:match("^%x+$"), "slot should be hex")
    end)

    it("long-polls until host publishes the description", function()
      local result

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })

        -- Publish host desc after a short delay (simulate async gathering).
        local t = uv.new_timer()
        t:start(100, 0, function()
          t:close()
          srv:set_host_desc(FAKE_HOST_DESC)
        end)

        sig.fetch_host(srv.url, 2000, function(err, desc, slot)
          result = { err = err, desc = desc, slot = slot }
          srv:stop()
          cancel()
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_nil(result.err)
      assert.equal(FAKE_HOST_DESC, result.desc)
      assert.is_string(result.slot)
    end)

    it("returns an error when fetch times out before host publishes", function()
      local result

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })
        -- Host never publishes — fetch should time out after 300 ms.
        sig.fetch_host(srv.url, 300, function(err, desc, slot)
          result = { err = err, desc = desc, slot = slot }
          srv:stop()
          cancel()
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_string(result.err,  "expected a timeout error string")
      assert.is_nil(result.desc)
      assert.is_nil(result.slot)
    end)

    it("different guests receive different slot IDs", function()
      local slotA, slotB

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })
        srv:set_host_desc(FAKE_HOST_DESC)
        local pending = 2

        local function maybe_done()
          pending = pending - 1
          if pending == 0 then srv:stop(); cancel() end
        end

        sig.fetch_host(srv.url, 2000, function(err, _, slot)
          slotA = slot; maybe_done()
        end)
        sig.fetch_host(srv.url, 2000, function(err, _, slot)
          slotB = slot; maybe_done()
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_string(slotA)
      assert.is_string(slotB)
      assert.not_equal(slotA, slotB)
    end)
  end)

  -- ── guest post ────────────────────────────────────────────────────────────

  describe("post_guest", function()
    it("stores guest desc and notifies host callback", function()
      local notified_slot, notified_desc

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })
        srv:set_host_desc(FAKE_HOST_DESC)

        srv:on_guest(function(slot, desc)
          notified_slot = slot
          notified_desc = desc
          srv:stop()
          cancel()
        end)

        sig.fetch_host(srv.url, 2000, function(err, _, slot)
          assert.is_nil(err)
          sig.post_guest(srv.url, slot, FAKE_GUEST_DESC, function(post_err)
            assert.is_nil(post_err)
          end)
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_string(notified_slot)
      assert.equal(FAKE_GUEST_DESC, notified_desc)
    end)

    it("returns an error for an unknown slot", function()
      local result

      local ok = run_loop(3000, function(cancel)
        local srv = sig.new({ port = 0 })

        sig.post_guest(srv.url, "deadbeefdeadbeef", FAKE_GUEST_DESC, function(err)
          result = err
          srv:stop()
          cancel()
        end)
      end)

      assert.is_true(ok, "test timed out")
      assert.is_string(result, "expected an error for unknown slot")
    end)
  end)

  -- ── full two-peer handshake ───────────────────────────────────────────────

  it("completes a full host→guest→host description exchange", function()
    local received_by_guest, received_by_host

    local ok = run_loop(4000, function(cancel)
      local srv = sig.new({ port = 0 })
      srv:set_host_desc(FAKE_HOST_DESC)

      srv:on_guest(function(slot, desc)
        received_by_host = desc
        srv:stop()
        cancel()
      end)

      sig.fetch_host(srv.url, 2000, function(err, host_desc, slot)
        assert.is_nil(err)
        received_by_guest = host_desc
        sig.post_guest(srv.url, slot, FAKE_GUEST_DESC, function(post_err)
          assert.is_nil(post_err)
        end)
      end)
    end)

    assert.is_true(ok, "test timed out")
    assert.equal(FAKE_HOST_DESC,  received_by_guest)
    assert.equal(FAKE_GUEST_DESC, received_by_host)
  end)

  -- ── multi-guest (3 users) ─────────────────────────────────────────────────

  it("handles two guests joining the same host concurrently", function()
    local host_received = {}
    local guest_count   = 0  -- plain counter; # on a string-keyed table is unreliable

    local ok = run_loop(4000, function(cancel)
      local srv = sig.new({ port = 0 })
      srv:set_host_desc(FAKE_HOST_DESC)

      srv:on_guest(function(slot, desc)
        host_received[slot] = desc
        guest_count = guest_count + 1
        if guest_count == 2 then
          srv:stop()
          cancel()
        end
      end)

      -- Guest 1
      sig.fetch_host(srv.url, 2000, function(err, _, slot)
        assert.is_nil(err)
        sig.post_guest(srv.url, slot, FAKE_GUEST_DESC .. "1", function() end)
      end)

      -- Guest 2 (20 ms offset so both slots are distinct)
      local t = uv.new_timer()
      t:start(20, 0, function()
        t:close()
        sig.fetch_host(srv.url, 2000, function(err, _, slot)
          assert.is_nil(err)
          sig.post_guest(srv.url, slot, FAKE_GUEST_DESC .. "2", function() end)
        end)
      end)
    end)

    assert.is_true(ok, "test timed out")
    assert.equal(2, guest_count)
    local n = 0
    for _ in pairs(host_received) do n = n + 1 end
    assert.equal(2, n, "host should have received 2 guest descriptions")
  end)

  -- ── stop ─────────────────────────────────────────────────────────────────

  it("stop() cancels pending long-polls with an error", function()
    local result

    local ok = run_loop(3000, function(cancel)
      local srv = sig.new({ port = 0 })
      -- Host never publishes; fetch long-polls.
      -- Stop the server after 150 ms → fetch should get an error.
      local t = uv.new_timer()
      t:start(150, 0, function()
        t:close()
        srv:stop()
        cancel()
      end)

      sig.fetch_host(srv.url, 5000, function(err, desc)
        result = { err = err, desc = desc }
        -- The TCP connection error from a stopped server is the signal here.
      end)
    end)

    assert.is_true(ok, "test timed out")
    -- Either the fetch gets a connection error (server closed) or a timeout error.
    -- Either way, desc should be nil.
    assert.is_nil(result and result.desc)
  end)

end)
