-- spec/ice_spec.lua
-- Unit tests for punch/ice.lua
--
-- Covers: candidate pair generation (make_pairs), priority ordering, and
-- relay×relay exclusion.  Does NOT test gather() or check_pairs() — those
-- require a live event loop and network; see spec/integration/.

local ice = require("punch.ice")

-- ── helpers ───────────────────────────────────────────────────────────────────

-- Build a minimal candidate table.  priority is optional; when nil, make_pairs
-- derives it from the type via candidate_priority (the module-internal formula).
local function cand(ctype, addr, port, priority)
  return {
    type     = ctype,
    addr     = addr or "127.0.0.1",
    port     = port or 12345,
    priority = priority,
  }
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("ice", function()

  -- ── make_pairs ────────────────────────────────────────────────────────────

  describe("make_pairs", function()
    it("returns an empty list when local candidates are empty", function()
      assert.equal(0, #ice.make_pairs({}, { cand("host") }))
    end)

    it("returns an empty list when remote candidates are empty", function()
      assert.equal(0, #ice.make_pairs({ cand("host") }, {}))
    end)

    it("returns an empty list when both inputs are empty", function()
      assert.equal(0, #ice.make_pairs({}, {}))
    end)

    it("creates n×m pairs from n local and m remote candidates", function()
      local local_cands  = { cand("host"), cand("srflx") }
      local remote_cands = { cand("host"), cand("srflx"), cand("host", "10.0.0.2") }
      assert.equal(6, #ice.make_pairs(local_cands, remote_cands))
    end)

    it("excludes relay×relay pairs", function()
      local local_cands  = { cand("relay"), cand("host") }
      local remote_cands = { cand("relay"), cand("host") }
      -- Possible pairs: relay×relay (excluded), relay×host, host×relay, host×host = 3
      local pairs = ice.make_pairs(local_cands, remote_cands)
      assert.equal(3, #pairs)
      for _, p in ipairs(pairs) do
        assert.is_false(
          p.local_cand.type == "relay" and p.remote_cand.type == "relay",
          "relay×relay pair should not appear in the list"
        )
      end
    end)

    it("includes host×relay pairs (non-symmetric relay)", function()
      local pairs = ice.make_pairs({ cand("host") }, { cand("relay") })
      assert.equal(1, #pairs)
      assert.equal("host",  pairs[1].local_cand.type)
      assert.equal("relay", pairs[1].remote_cand.type)
    end)

    it("initialises each pair's state to 'waiting'", function()
      local pairs = ice.make_pairs({ cand("host") }, { cand("host") })
      for _, p in ipairs(pairs) do
        assert.equal("waiting", p.state)
      end
    end)

    it("stores references to the original candidate tables", function()
      local lc = cand("host",  "192.168.1.1", 10000)
      local rc = cand("srflx", "203.0.113.1", 20000)
      local pairs = ice.make_pairs({ lc }, { rc })
      assert.equal(1, #pairs)
      assert.equal(lc, pairs[1].local_cand)
      assert.equal(rc, pairs[1].remote_cand)
    end)

    it("each pair has a numeric priority field", function()
      local pairs = ice.make_pairs({ cand("host") }, { cand("srflx") })
      assert.equal(1, #pairs)
      assert.equal("number", type(pairs[1].priority))
      assert.truthy(pairs[1].priority > 0)
    end)
  end)

  -- ── check_pairs ───────────────────────────────────────────────────────────

  describe("check_pairs", function()
    it("calls back with error immediately on empty pair list", function()
      local got_err
      ice.check_pairs({}, {}, {}, function(err) got_err = err end)
      assert.is_string(got_err, "expected error string for empty list")
    end)

    -- Full connectivity check tests (with a live event loop) are in
    -- spec/integration/punch_loopback_spec.lua.
  end)

  -- ── priority ordering ─────────────────────────────────────────────────────

  describe("priority ordering", function()
    it("pairs are sorted by priority descending", function()
      -- Mix of types to exercise the sort path.
      local local_cands  = { cand("host"), cand("srflx"), cand("relay") }
      local remote_cands = { cand("host"), cand("srflx") }
      local pairs = ice.make_pairs(local_cands, remote_cands)
      for i = 1, #pairs - 1 do
        assert.truthy(
          pairs[i].priority >= pairs[i + 1].priority,
          string.format(
            "pair %d (%.0f) has lower priority than pair %d (%.0f)",
            i, pairs[i].priority, i + 1, pairs[i + 1].priority
          )
        )
      end
    end)

    it("host×host has higher priority than host×srflx", function()
      local pairs = ice.make_pairs(
        { cand("host") },
        { cand("host"), cand("srflx") }
      )
      -- First (highest priority) pair should be host×host.
      assert.equal("host",  pairs[1].local_cand.type)
      assert.equal("host",  pairs[1].remote_cand.type)
      assert.equal("srflx", pairs[2].remote_cand.type)
    end)

    it("host×host has higher priority than srflx×srflx", function()
      local hh = ice.make_pairs({ cand("host") },  { cand("host") })
      local ss = ice.make_pairs({ cand("srflx") }, { cand("srflx") })
      assert.equal(1, #hh)
      assert.equal(1, #ss)
      assert.truthy(hh[1].priority > ss[1].priority)
    end)

    it("srflx×srflx has higher priority than relay×host", function()
      -- relay has type_pref = 0, so any relay pair should be lower than
      -- a pure srflx pair.
      local ss = ice.make_pairs({ cand("srflx") }, { cand("srflx") })
      local rh = ice.make_pairs({ cand("relay") }, { cand("host") })
      assert.equal(1, #ss)
      assert.equal(1, #rh)
      assert.truthy(ss[1].priority > rh[1].priority)
    end)

    it("explicit priority overrides the type-derived value", function()
      -- Give a relay candidate an artificially high priority and confirm it
      -- sorts before a host candidate with the default priority.
      local relay_hi   = cand("relay", "127.0.0.1", 1000, 2^32)
      local host_def   = cand("host",  "127.0.0.1", 2000)
      local pairs = ice.make_pairs({ relay_hi }, { host_def })
      assert.equal(1, #pairs)
      local pairs2 = ice.make_pairs({ host_def }, { cand("host", "127.0.0.1", 3000) })
      -- relay_hi × host_def should have priority > host_def × host_def
      -- because we set relay_hi.priority = 2^32 (huge).
      assert.truthy(pairs[1].priority > pairs2[1].priority)
    end)
  end)

end)
