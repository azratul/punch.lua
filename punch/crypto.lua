-- punch/crypto.lua
-- AES-256-GCM encryption and X25519 ECDH key exchange, via LuaJIT FFI → OpenSSL.
--
-- Graceful fallback: if OpenSSL is unavailable, crypto.available = false and
-- all encrypt/decrypt calls return the plaintext unchanged with a warning.
-- Callers should check crypto.available and warn the user accordingly.
--
-- Wire format for an encrypted payload:
--   [ 12-byte nonce ][ ciphertext ][ 16-byte GCM authentication tag ]
--
-- ── API ───────────────────────────────────────────────────────────────────────
--
--   crypto.available           — bool: true if OpenSSL AES-GCM is loaded
--   crypto.ecdh_available      — bool: true if X25519 ECDH is available
--
--   crypto.generate_key()      → 32-byte random key string
--   crypto.random_bytes(n)     → n random bytes as a string
--   crypto.encrypt(key, plain) → nonce..cipher..tag  | nil, err
--   crypto.decrypt(key, data)  → plaintext           | nil, err
--
--   crypto.ecdh_keygen()                    → { pub=32b, priv=32b } | nil, err
--   crypto.ecdh_derive(keypair, remote_pub) → 32-byte AES key      | nil, err
--     KDF: SHA-256("punch.lua\0" || X25519(priv,remote_pub))
--
--   crypto.sha256(data)      → 32-byte digest | nil, err
--   crypto.b64_encode(str)   → base64 string
--   crypto.b64_decode(str)   → binary string  | nil, err
local M = {}

M.available      = false
M.ecdh_available = false

-- ── FFI setup ─────────────────────────────────────────────────────────────────

local ffi_ok, ffi = pcall(require, "ffi")
if not ffi_ok then
  -- Not LuaJIT — no FFI available.
  return M
end

ffi.cdef [[
  /* Random */
  int RAND_bytes(unsigned char *buf, int num);

  /* EVP AEAD (AES-256-GCM) */
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

  const EVP_CIPHER *EVP_aes_256_gcm(void);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in,  int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
  int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in,  int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  /* EVP PKEY (X25519 ECDH) */
  typedef struct evp_pkey_st     EVP_PKEY;
  typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;

  EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, void *e);
  EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, void *e);
  void          EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
  int           EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
  int           EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
  void          EVP_PKEY_free(EVP_PKEY *pkey);

  EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *e,
                                         const unsigned char *key, size_t keylen);
  EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, void *e,
                                          const unsigned char *key, size_t keylen);
  int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey,
                                   unsigned char *pub, size_t *len);
  int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey,
                                    unsigned char *priv, size_t *len);

  int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
  int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);

  /* SHA-256 and HMAC */
  const void *EVP_sha256(void);
  unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
  unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                      const unsigned char *d, size_t n, unsigned char *md,
                      unsigned int *md_len);
]]

local EVP_CTRL_GCM_SET_IVLEN  = 0x9
local EVP_CTRL_GCM_GET_TAG    = 0x10
local EVP_CTRL_GCM_SET_TAG    = 0x11

local NONCE_LEN = 12
local TAG_LEN   = 16

local lib
do
  local names = { "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", "libssl.so" }
  for _, name in ipairs(names) do
    local ok, l = pcall(ffi.load, name)
    if ok then lib = l; break end
  end
end

if not lib then
  return M  -- OpenSSL not found; M.available stays false
end

M.available = true

-- ── Random bytes ──────────────────────────────────────────────────────────────

function M.random_bytes(n)
  local buf = ffi.new("unsigned char[?]", n)
  if lib.RAND_bytes(buf, n) ~= 1 then
    error("crypto: RAND_bytes failed")
  end
  return ffi.string(buf, n)
end

function M.generate_key()
  return M.random_bytes(32)
end

-- ── SHA-256 ───────────────────────────────────────────────────────────────────

function M.sha256(data)
  local digest = ffi.new("unsigned char[32]")
  if lib.SHA256(data, #data, digest) == nil then
    return nil, "SHA256 failed"
  end
  return ffi.string(digest, 32)
end

-- ── HMAC-SHA256 ──────────────────────────────────────────────────────────────

function M.hmac_sha256(key, data)
  local digest = ffi.new("unsigned char[32]")
  local dlen   = ffi.new("unsigned int[1]")
  if lib.HMAC(lib.EVP_sha256(), key, #key, data, #data, digest, dlen) == nil then
    return nil, "HMAC-SHA256 failed"
  end
  return ffi.string(digest, 32)
end

-- ── HKDF-SHA256 (Extract-then-Expand) ────────────────────────────────────────
-- Implements RFC 5869.
--
-- secret — Input Keying Material (IKM)
-- info   — optional context info string
-- salt   — optional salt string (default: 32 zeros)
function M.hkdf_sha256(secret, info, salt)
  salt = salt or string.rep("\0", 32)
  info = info or ""
  -- 1. Extract: PRK = HMAC(salt, secret)
  local prk = M.hmac_sha256(salt, secret)
  if not prk then return nil, "HKDF Extract failed" end
  -- 2. Expand: T(1) = HMAC(PRK, info || 0x01)
  local t1 = M.hmac_sha256(prk, info .. "\01")
  return t1  -- returns 32 bytes (enough for AES-256)
end

-- ── X25519 ECDH ───────────────────────────────────────────────────────────────
--
-- X25519 (RFC 7748) provides forward-secret key agreement.
-- Both peers exchange 32-byte public keys out-of-band (in the description).
-- The shared AES key is derived as:
--   SHA-256("punch.lua\0" || X25519(local_priv, remote_pub))
--
-- EVP_PKEY_X25519 = 1034 (OpenSSL 1.1+)

local EVP_PKEY_X25519 = 1034

do
  local test_ok = pcall(function()
    local ctx = lib.EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nil)
    if ctx == nil then error("unsupported") end
    lib.EVP_PKEY_CTX_free(ctx)
  end)
  M.ecdh_available = test_ok
end

-- Generate an ephemeral X25519 keypair.
-- Returns { pub = 32-byte string, priv = 32-byte string } or nil, err.
function M.ecdh_keygen()
  if not M.ecdh_available then return nil, "X25519 not available in this OpenSSL" end

  local ctx = lib.EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nil)
  if ctx == nil then return nil, "EVP_PKEY_CTX_new_id failed" end

  local ok   = lib.EVP_PKEY_keygen_init(ctx) == 1
  local pptr = ffi.new("EVP_PKEY*[1]")
  if ok then ok = lib.EVP_PKEY_keygen(ctx, pptr) == 1 end
  lib.EVP_PKEY_CTX_free(ctx)
  if not ok or pptr[0] == nil then return nil, "EVP_PKEY_keygen failed" end

  local pkey    = pptr[0]
  local pub_buf = ffi.new("unsigned char[32]")
  local pub_len = ffi.new("size_t[1]", 32)
  local prv_buf = ffi.new("unsigned char[32]")
  local prv_len = ffi.new("size_t[1]", 32)

  local got_pub = lib.EVP_PKEY_get_raw_public_key(pkey, pub_buf, pub_len)  == 1
  local got_prv = lib.EVP_PKEY_get_raw_private_key(pkey, prv_buf, prv_len) == 1
  lib.EVP_PKEY_free(pkey)

  if not got_pub or not got_prv then return nil, "failed to export keypair" end

  return { pub = ffi.string(pub_buf, 32), priv = ffi.string(prv_buf, 32) }
end

-- Derive a shared 32-byte AES key from a local keypair and a remote public key.
-- keypair     — table returned by ecdh_keygen() (must have .priv 32-byte string)
-- remote_pub  — 32-byte raw public key string from the remote peer's description
function M.ecdh_derive(keypair, remote_pub)
  if not M.ecdh_available then return nil, "X25519 not available" end
  if type(keypair) ~= "table" or #(keypair.priv or "") ~= 32 then
    return nil, "keypair.priv must be a 32-byte string"
  end
  if #remote_pub ~= 32 then return nil, "remote_pub must be 32 bytes" end

  local lpriv = lib.EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nil, keypair.priv, 32)
  if lpriv == nil then return nil, "failed to import local private key" end

  local rpub = lib.EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nil, remote_pub, 32)
  if rpub == nil then lib.EVP_PKEY_free(lpriv); return nil, "failed to import remote public key" end

  local dctx   = lib.EVP_PKEY_CTX_new(lpriv, nil)
  local secret, serr

  if dctx == nil then
    serr = "EVP_PKEY_CTX_new failed"
  else
    if lib.EVP_PKEY_derive_init(dctx) ~= 1 then
      serr = "EVP_PKEY_derive_init failed"
    elseif lib.EVP_PKEY_derive_set_peer(dctx, rpub) ~= 1 then
      serr = "EVP_PKEY_derive_set_peer failed"
    else
      local slen = ffi.new("size_t[1]")
      if lib.EVP_PKEY_derive(dctx, nil, slen) == 1 then
        local sbuf = ffi.new("unsigned char[?]", slen[0])
        if lib.EVP_PKEY_derive(dctx, sbuf, slen) == 1 then
          -- Domain-separate the KDF so keys can't be reused across protocols.
          local raw = ffi.string(sbuf, slen[0])
          secret = M.hkdf_sha256(raw, "punch.lua\0session-key")
        else
          serr = "EVP_PKEY_derive failed"
        end
      else
        serr = "EVP_PKEY_derive (size query) failed"
      end
    end
    lib.EVP_PKEY_CTX_free(dctx)
  end

  lib.EVP_PKEY_free(lpriv)
  lib.EVP_PKEY_free(rpub)

  if not secret then return nil, serr end
  return secret
end

-- ── Base64 ────────────────────────────────────────────────────────────────────

local _B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function M.b64_encode(s)
  local res, i = {}, 1
  while i <= #s do
    local b1, b2, b3 = s:byte(i), s:byte(i+1) or 0, s:byte(i+2) or 0
    local n = b1 * 65536 + b2 * 256 + b3
    res[#res+1] = _B64:sub(math.floor(n / 262144) + 1,    math.floor(n / 262144) + 1)
    res[#res+1] = _B64:sub(math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1)
    res[#res+1] = (i + 1 <= #s) and _B64:sub(math.floor(n / 64) % 64 + 1,
                                              math.floor(n / 64) % 64 + 1) or "="
    res[#res+1] = (i + 2 <= #s) and _B64:sub(n % 64 + 1, n % 64 + 1) or "="
    i = i + 3
  end
  return table.concat(res)
end

function M.b64_decode(s)
  local rev = {}
  for i = 1, #_B64 do rev[_B64:sub(i, i)] = i - 1 end
  s = s:gsub("[^%w+/=]", "")
  if #s % 4 ~= 0 then return nil, "invalid base64 length" end
  local res = {}
  for i = 1, #s, 4 do
    local a = rev[s:sub(i,   i)]   or 0
    local b = rev[s:sub(i+1, i+1)] or 0
    local c = rev[s:sub(i+2, i+2)] or 0
    local d = rev[s:sub(i+3, i+3)] or 0
    local n = a * 262144 + b * 4096 + c * 64 + d
    res[#res+1] = string.char(math.floor(n / 65536) % 256)
    if s:sub(i+2, i+2) ~= "=" then res[#res+1] = string.char(math.floor(n / 256) % 256) end
    if s:sub(i+3, i+3) ~= "=" then res[#res+1] = string.char(n % 256) end
  end
  return table.concat(res)
end

-- ── Encrypt ───────────────────────────────────────────────────────────────────

function M.encrypt(key, plaintext)
  if #key ~= 32 then return nil, "key must be 32 bytes" end

  local nonce = M.random_bytes(NONCE_LEN)
  local plen  = #plaintext
  local ctx   = lib.EVP_CIPHER_CTX_new()
  if ctx == nil then return nil, "EVP_CIPHER_CTX_new failed" end

  local ok = true
  local result

  repeat
    if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), nil, nil, nil) ~= 1 then
      ok = false; break
    end
    if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nil) ~= 1 then
      ok = false; break
    end
    if lib.EVP_EncryptInit_ex(ctx, nil, nil, key, nonce) ~= 1 then
      ok = false; break
    end

    local outbuf = ffi.new("unsigned char[?]", plen + 16)
    local outlen = ffi.new("int[1]")

    if lib.EVP_EncryptUpdate(ctx, outbuf, outlen, plaintext, plen) ~= 1 then
      ok = false; break
    end
    local clen = outlen[0]

    local finalbuf = ffi.new("unsigned char[16]")
    local finallen = ffi.new("int[1]")
    if lib.EVP_EncryptFinal_ex(ctx, finalbuf, finallen) ~= 1 then
      ok = false; break
    end

    local tag = ffi.new("unsigned char[?]", TAG_LEN)
    if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) ~= 1 then
      ok = false; break
    end

    result = nonce .. ffi.string(outbuf, clen) .. ffi.string(tag, TAG_LEN)
  until true

  lib.EVP_CIPHER_CTX_free(ctx)
  if not ok then return nil, "AES-GCM encrypt failed" end
  return result
end

-- ── Decrypt ───────────────────────────────────────────────────────────────────

function M.decrypt(key, data)
  if #key ~= 32 then return nil, "key must be 32 bytes" end
  if #data < NONCE_LEN + TAG_LEN then return nil, "data too short" end

  local nonce      = data:sub(1, NONCE_LEN)
  local ciphertext = data:sub(NONCE_LEN + 1, #data - TAG_LEN)
  local tag_str    = data:sub(#data - TAG_LEN + 1)
  local clen       = #ciphertext

  local ctx = lib.EVP_CIPHER_CTX_new()
  if ctx == nil then return nil, "EVP_CIPHER_CTX_new failed" end

  local ok = true
  local result

  repeat
    if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), nil, nil, nil) ~= 1 then
      ok = false; break
    end
    if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nil) ~= 1 then
      ok = false; break
    end
    if lib.EVP_DecryptInit_ex(ctx, nil, nil, key, nonce) ~= 1 then
      ok = false; break
    end

    local outbuf = ffi.new("unsigned char[?]", clen + 16)
    local outlen = ffi.new("int[1]")

    if lib.EVP_DecryptUpdate(ctx, outbuf, outlen, ciphertext, clen) ~= 1 then
      ok = false; break
    end
    local plen = outlen[0]

    local tag_buf = ffi.new("unsigned char[?]", TAG_LEN)
    ffi.copy(tag_buf, tag_str, TAG_LEN)
    if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag_buf) ~= 1 then
      ok = false; break
    end

    local finalbuf = ffi.new("unsigned char[16]")
    local finallen = ffi.new("int[1]")
    if lib.EVP_DecryptFinal_ex(ctx, finalbuf, finallen) ~= 1 then
      ok = false; break  -- authentication tag mismatch
    end

    result = ffi.string(outbuf, plen)
  until true

  lib.EVP_CIPHER_CTX_free(ctx)
  if not ok then return nil, "AES-GCM decrypt failed (bad key or tampered data)" end
  return result
end

return M
