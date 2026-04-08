-- spec/signal_spec.lua
-- Unit tests for punch/signal.lua
--
-- Covers: encode/decode round-trips, field preservation, validation errors.
-- No network I/O — all tests are synchronous.

local signal = require("punch.signal")

-- ── helpers ───────────────────────────────────────────────────────────────────

-- Minimal valid description with one host candidate.
local function make_desc(overrides)
  local d = {
    token      = "deadbeefcafe0000",
    candidates = {
      { type = "host", addr = "192.168.1.5", port = 54321 },
    },
  }
  if overrides then
    for k, v in pairs(overrides) do d[k] = v end
  end
  return d
end

-- encode then decode in one step.
local function roundtrip(desc)
  local str, err = signal.encode(desc)
  if not str then return nil, nil, err end
  local decoded, derr = signal.decode(str)
  return str, decoded, derr
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("signal", function()

  -- ── encode / decode round-trips ───────────────────────────────────────────

  describe("encode / decode round-trip", function()
    it("preserves a single host candidate", function()
      local str, decoded, err = roundtrip(make_desc())
      assert.is_nil(err)
      assert.is_string(str)
      assert.equal(1, #decoded.candidates)
      local c = decoded.candidates[1]
      assert.equal("host",        c.type)
      assert.equal("192.168.1.5", c.addr)
      assert.equal(54321,         c.port)
    end)

    it("preserves the token", function()
      local _, decoded = roundtrip(make_desc({ token = "0011223344556677" }))
      assert.equal("0011223344556677", decoded.token)
    end)

    it("preserves the pub field (ECDH public key)", function()
      local pub  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      local _, decoded = roundtrip(make_desc({ pub = pub }))
      assert.equal(pub, decoded.pub)
    end)

    it("omits pub from the decoded table when it was nil", function()
      local _, decoded = roundtrip(make_desc())
      assert.is_nil(decoded.pub)
    end)

    it("preserves multiple candidates in order", function()
      local desc = make_desc({
        candidates = {
          { type = "host",  addr = "10.0.0.1",       port = 1111 },
          { type = "srflx", addr = "203.0.113.5",     port = 2222 },
          { type = "relay", addr = "relay.example.com", port = 443, relay_token = "rt_secret" },
        },
      })
      local _, decoded, err = roundtrip(desc)
      assert.is_nil(err)
      assert.equal(3, #decoded.candidates)
      assert.equal("host",  decoded.candidates[1].type)
      assert.equal("srflx", decoded.candidates[2].type)
      assert.equal("relay", decoded.candidates[3].type)
    end)

    it("preserves relay_token on a relay candidate", function()
      local desc = make_desc({
        candidates = {
          { type = "relay", addr = "r.example.com", port = 443, relay_token = "tok_xyz" },
        },
      })
      local _, decoded = roundtrip(desc)
      assert.equal("tok_xyz", decoded.candidates[1].relay_token)
    end)

    it("does not add relay_token when absent", function()
      local _, decoded = roundtrip(make_desc())
      assert.is_nil(decoded.candidates[1].relay_token)
    end)

    it("preserves integer ports exactly (no float drift)", function()
      local _, decoded = roundtrip(make_desc({
        candidates = { { type = "host", addr = "1.2.3.4", port = 65535 } }
      }))
      assert.equal(65535, decoded.candidates[1].port)
      assert.equal("number", type(decoded.candidates[1].port))
    end)

    it("sets version = 1 in the decoded table", function()
      local _, decoded = roundtrip(make_desc())
      assert.equal(1, decoded.version)
    end)
  end)

  -- ── encode validation ─────────────────────────────────────────────────────

  describe("encode validation", function()
    it("fails when desc is not a table", function()
      local result, err = signal.encode("not a table")
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails when candidates is nil", function()
      local result, err = signal.encode({ token = "x" })
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails when candidates is an empty table", function()
      local result, err = signal.encode({ token = "x", candidates = {} })
      assert.is_nil(result)
      assert.is_string(err)
    end)
  end)

  -- ── decode validation ─────────────────────────────────────────────────────

  describe("decode validation", function()
    it("fails on an empty string", function()
      local result, err = signal.decode("")
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails when the input is not a string", function()
      local result, err = signal.decode(42)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails on malformed JSON", function()
      local result, err = signal.decode("{not: valid json}")
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails on a JSON non-object (array)", function()
      local result, err = signal.decode("[]")
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails when the protocol version is wrong", function()
      local json = '{"v":99,"token":"abcd1234abcd1234","candidates":[{"t":"host","a":"1.2.3.4","p":1234}]}'
      local result, err = signal.decode(json)
      assert.is_nil(result)
      assert.is_string(err)
      -- Error message should mention the version problem.
      assert.truthy(err:lower():find("version") or err:lower():find("unsupported"),
        "expected error to mention 'version' or 'unsupported', got: " .. err)
    end)

    it("fails when candidates is an empty array", function()
      local json = '{"v":1,"token":"abcd1234abcd1234","candidates":[]}'
      local result, err = signal.decode(json)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails on a candidate missing the address field", function()
      local json = '{"v":1,"token":"abcd1234abcd1234","candidates":[{"t":"host","p":1234}]}'
      local result, err = signal.decode(json)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("fails on a candidate with a non-number port", function()
      local json = '{"v":1,"token":"abcd1234abcd1234","candidates":[{"t":"host","a":"1.2.3.4","p":"not_a_port"}]}'
      local result, err = signal.decode(json)
      assert.is_nil(result)
      assert.is_string(err)
    end)
  end)

end)
