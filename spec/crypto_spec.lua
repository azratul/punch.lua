-- spec/crypto_spec.lua
-- Unit tests for punch/crypto.lua
--
-- Covers: random bytes, AES-256-GCM encrypt/decrypt, base64, SHA-256, ECDH.
-- Tests that require OpenSSL or X25519 are skipped with pending() when the
-- library is unavailable (e.g. no libcrypto on the machine).

local bit    = require("bit")
local crypto = require("punch.crypto")

-- ── helpers ───────────────────────────────────────────────────────────────────

local function skip_no_crypto()
  if not crypto.available then pending("OpenSSL not available") end
end

local function skip_no_ecdh()
  if not crypto.ecdh_available then pending("X25519 not available in this OpenSSL") end
end

-- Flip one byte at position i in string s.
local function flip_byte(s, i)
  return s:sub(1, i - 1)
      .. string.char(bit.bxor(s:byte(i), 0xFF))
      .. s:sub(i + 1)
end

-- ── tests ─────────────────────────────────────────────────────────────────────

describe("crypto", function()

  -- ── random_bytes ──────────────────────────────────────────────────────────

  describe("random_bytes", function()
    it("returns a string of the requested length", function()
      skip_no_crypto()
      local b = crypto.random_bytes(16)
      assert.is_string(b)
      assert.equal(16, #b)
    end)

    it("returns different values on successive calls", function()
      skip_no_crypto()
      -- Probability of collision for 32 random bytes: ~1/2^256. Safe to assert.
      assert.not_equal(crypto.random_bytes(32), crypto.random_bytes(32))
    end)
  end)

  -- ── generate_key ──────────────────────────────────────────────────────────

  describe("generate_key", function()
    it("returns exactly 32 bytes", function()
      skip_no_crypto()
      local k = crypto.generate_key()
      assert.is_string(k)
      assert.equal(32, #k)
    end)
  end)

  -- ── encrypt / decrypt ─────────────────────────────────────────────────────

  describe("encrypt / decrypt", function()
    before_each(skip_no_crypto)

    it("round-trips a plaintext string", function()
      local key   = crypto.generate_key()
      local plain = "hello, world"
      local ct    = crypto.encrypt(key, plain)
      assert.is_string(ct)
      -- wire format: nonce(12) + ciphertext(len) + tag(16)
      assert.equal(12 + #plain + 16, #ct)
      assert.equal(plain, crypto.decrypt(key, ct))
    end)

    it("round-trips an empty payload", function()
      local key = crypto.generate_key()
      local ct  = crypto.encrypt(key, "")
      assert.equal(12 + 0 + 16, #ct)
      assert.equal("", crypto.decrypt(key, ct))
    end)

    it("round-trips arbitrary binary data", function()
      local key   = crypto.generate_key()
      local plain = string.rep("\x00\xFF\xAA\x55", 64)  -- 256 bytes
      assert.equal(plain, crypto.decrypt(key, crypto.encrypt(key, plain)))
    end)

    it("uses a fresh nonce each time (ciphertexts differ for same input)", function()
      local key = crypto.generate_key()
      local c1  = crypto.encrypt(key, "same input")
      local c2  = crypto.encrypt(key, "same input")
      assert.not_equal(c1, c2)
    end)

    it("decrypt fails with the wrong key", function()
      local key1 = crypto.generate_key()
      local key2 = crypto.generate_key()
      local ct   = crypto.encrypt(key1, "secret")
      local result, err = crypto.decrypt(key2, ct)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("decrypt fails when the ciphertext body is tampered", function()
      local key = crypto.generate_key()
      local ct  = crypto.encrypt(key, "hello, world")
      -- Flip a byte in the middle of the ciphertext (past the 12-byte nonce)
      local tampered = flip_byte(ct, 13)
      local result, err = crypto.decrypt(key, tampered)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("decrypt fails when the authentication tag is tampered", function()
      local key = crypto.generate_key()
      local ct  = crypto.encrypt(key, "hello, world")
      -- Flip the last byte (part of the 16-byte GCM tag)
      local tampered = flip_byte(ct, #ct)
      local result, err = crypto.decrypt(key, tampered)
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("encrypt returns nil for a key shorter than 32 bytes", function()
      local result, err = crypto.encrypt("too_short", "data")
      assert.is_nil(result)
      assert.is_string(err)
    end)

    it("decrypt returns nil for data shorter than nonce + tag (28 bytes)", function()
      local key = crypto.generate_key()
      local result, err = crypto.decrypt(key, "short")
      assert.is_nil(result)
      assert.is_string(err)
    end)
  end)

  -- ── base64 ────────────────────────────────────────────────────────────────

  describe("base64", function()
    -- RFC 4648 test vectors
    local vectors = {
      { plain = "f",      b64 = "Zg=="     },
      { plain = "fo",     b64 = "Zm8="     },
      { plain = "foo",    b64 = "Zm9v"     },
      { plain = "foob",   b64 = "Zm9vYg==" },
      { plain = "fooba",  b64 = "Zm9vYmE=" },
      { plain = "foobar", b64 = "Zm9vYmFy" },
    }

    for _, v in ipairs(vectors) do
      it(string.format("encodes %q to %q", v.plain, v.b64), function()
        assert.equal(v.b64, crypto.b64_encode(v.plain))
      end)

      it(string.format("decodes %q to %q", v.b64, v.plain), function()
        assert.equal(v.plain, crypto.b64_decode(v.b64))
      end)
    end

    it("round-trips binary data", function()
      local bin = string.rep("\x00\xFF\xFE\x01\xAB\xCD", 20)
      assert.equal(bin, crypto.b64_decode(crypto.b64_encode(bin)))
    end)

    it("b64_encode of empty string is empty string", function()
      assert.equal("", crypto.b64_encode(""))
    end)

    it("b64_decode rejects a string whose length is not a multiple of 4", function()
      local result, err = crypto.b64_decode("abc")
      assert.is_nil(result)
      assert.is_string(err)
    end)
  end)

  -- ── sha256 ────────────────────────────────────────────────────────────────

  describe("sha256", function()
    before_each(skip_no_crypto)

    it("returns a 32-byte digest", function()
      local h = crypto.sha256("hello")
      assert.is_string(h)
      assert.equal(32, #h)
    end)

    it("is deterministic", function()
      assert.equal(crypto.sha256("hello"), crypto.sha256("hello"))
    end)

    it("produces different digests for different inputs", function()
      assert.not_equal(crypto.sha256("hello"), crypto.sha256("world"))
    end)

    it("matches the known SHA-256 digest of the empty string", function()
      -- SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
      local expected =
          "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
       .. "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
      assert.equal(expected, crypto.sha256(""))
    end)
  end)

  -- ── ECDH ──────────────────────────────────────────────────────────────────

  describe("ECDH (X25519)", function()
    before_each(function()
      skip_no_crypto()
      skip_no_ecdh()
    end)

    it("ecdh_keygen returns a table with 32-byte pub and priv", function()
      local kp, err = crypto.ecdh_keygen()
      assert.is_nil(err)
      assert.is_table(kp)
      assert.equal(32, #kp.pub)
      assert.equal(32, #kp.priv)
    end)

    it("ecdh_keygen produces different keypairs each call", function()
      local kpA = crypto.ecdh_keygen()
      local kpB = crypto.ecdh_keygen()
      assert.not_equal(kpA.pub,  kpB.pub)
      assert.not_equal(kpA.priv, kpB.priv)
    end)

    it("ecdh_derive is symmetric: derive(A, B.pub) == derive(B, A.pub)", function()
      local kpA = crypto.ecdh_keygen()
      local kpB = crypto.ecdh_keygen()
      local keyAB = crypto.ecdh_derive(kpA, kpB.pub)
      local keyBA = crypto.ecdh_derive(kpB, kpA.pub)
      assert.is_string(keyAB)
      assert.equal(32, #keyAB)
      assert.equal(keyAB, keyBA)
    end)

    it("ecdh_derive produces a 32-byte key usable with AES-256", function()
      local kpA = crypto.ecdh_keygen()
      local kpB = crypto.ecdh_keygen()
      local key = crypto.ecdh_derive(kpA, kpB.pub)
      assert.equal(32, #key)
    end)

    it("ecdh_derive rejects a remote_pub shorter than 32 bytes", function()
      local kp       = crypto.ecdh_keygen()
      local _, err   = crypto.ecdh_derive(kp, "too_short")
      assert.is_nil(_)
      assert.is_string(err)
    end)

    it("encrypt/decrypt round-trips with an ECDH-derived session key", function()
      local kpA = crypto.ecdh_keygen()
      local kpB = crypto.ecdh_keygen()
      local key = crypto.ecdh_derive(kpA, kpB.pub)
      local msg = "encrypted with a shared secret"
      assert.equal(msg, crypto.decrypt(key, crypto.encrypt(key, msg)))
    end)

    it("different keypair pairs produce different shared secrets", function()
      local kpA  = crypto.ecdh_keygen()
      local kpB  = crypto.ecdh_keygen()
      local kpC  = crypto.ecdh_keygen()
      local keyAB = crypto.ecdh_derive(kpA, kpB.pub)
      local keyAC = crypto.ecdh_derive(kpA, kpC.pub)
      assert.not_equal(keyAB, keyAC)
    end)
  end)

end)
