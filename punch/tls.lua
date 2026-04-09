-- punch/tls.lua
-- Client-side TLS wrapping via OpenSSL memory BIOs.
--
-- Wraps a connected uv.tcp handle in a TLS session and returns a transparent
-- adapter with the same API so callers can treat it like a plain TCP handle:
--
--   adapter:write(data)
--   adapter:read_start(fn)      fn(err, data)
--   adapter:read_stop()
--   adapter:is_closing()  → bool
--   adapter:close()
--
-- Usage:
--   local tls = require("punch.tls")
--   if tls.available then
--     tls.wrap(tcp, host, function(err, adapter) ... end)
--   end
local M = {}

local ffi_ok, ffi = pcall(require, "ffi")
local ssl_lib     = nil

if ffi_ok then
  pcall(function()
    ffi.cdef [[
      typedef struct ssl_ctx_st    SSL_CTX;
      typedef struct ssl_st        SSL;
      typedef struct bio_st        BIO;
      typedef struct bio_method_st BIO_METHOD;

      const SSL_METHOD *TLS_client_method(void);
      SSL_CTX  *SSL_CTX_new(const SSL_METHOD *method);
      void      SSL_CTX_free(SSL_CTX *ctx);
      SSL      *SSL_new(SSL_CTX *ctx);
      void      SSL_free(SSL *ssl);

      const BIO_METHOD *BIO_s_mem(void);
      BIO    *BIO_new(const BIO_METHOD *type);
      int     BIO_free(BIO *a);
      int     BIO_read(BIO *b, void *data, int dlen);
      int     BIO_write(BIO *b, const void *data, int len);
      size_t  BIO_ctrl_pending(BIO *b);

      void  SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
      void  SSL_set_connect_state(SSL *s);
      long  SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
      int   SSL_do_handshake(SSL *s);
      int   SSL_get_error(SSL *s, int ret);
      int   SSL_write(SSL *s, const void *buf, int num);
      int   SSL_read(SSL *s, void *buf, int num);
    ]]
  end) -- ignore "already declared" if loaded twice

  for _, name in ipairs({ "libssl.so.3", "libssl.so.1.1", "libssl.so" }) do
    local ok, l = pcall(ffi.load, name)
    if ok then
      ssl_lib = l
      break
    end
  end
end

-- True when libssl was loaded and TLS wrapping is usable.
M.available = ssl_lib ~= nil

local _SSL_ERROR_WANT_READ          = 2
local _SSL_ERROR_WANT_WRITE         = 3
local _SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
local _TLSEXT_NAMETYPE_host_name    = 0

-- wrap(tcp, host, callback)
--
-- tcp      — a connected uv.tcp handle
-- host     — SNI hostname (string)
-- callback(err, adapter)
--
-- On success, the callback receives nil error and the TLS adapter.
-- The adapter is ready for immediate use; no further handshaking needed.
function M.wrap(tcp, host, callback)
  if not ssl_lib then
    callback("TLS requires libssl (OpenSSL ≥ 1.1) — install it or use plain http://")
    return
  end

  local ctx = ssl_lib.SSL_CTX_new(ssl_lib.TLS_client_method())
  if ctx == nil then
    callback("SSL_CTX_new failed")
    return
  end

  local ssl = ssl_lib.SSL_new(ctx)
  ssl_lib.SSL_CTX_free(ctx) -- SSL holds its own reference
  if ssl == nil then
    callback("SSL_new failed")
    return
  end

  local rbio = ssl_lib.BIO_new(ssl_lib.BIO_s_mem())
  local wbio = ssl_lib.BIO_new(ssl_lib.BIO_s_mem())
  if rbio == nil or wbio == nil then
    if rbio ~= nil then ssl_lib.BIO_free(rbio) end
    if wbio ~= nil then ssl_lib.BIO_free(wbio) end
    ssl_lib.SSL_free(ssl)
    callback("BIO_new failed")
    return
  end

  ssl_lib.SSL_set_bio(ssl, rbio, wbio) -- SSL now owns both BIOs
  ssl_lib.SSL_set_connect_state(ssl)
  -- Set SNI so servers using virtual hosting respond with the right certificate.
  ssl_lib.SSL_ctrl(ssl, _SSL_CTRL_SET_TLSEXT_HOSTNAME, _TLSEXT_NAMETYPE_host_name, ffi.cast("void*", host))

  -- Flush everything SSL has queued in wbio out to the TCP socket.
  local function flush_wbio()
    local pending = ssl_lib.BIO_ctrl_pending(wbio)
    while pending > 0 do
      local buf = ffi.new("char[?]", pending)
      local n   = ssl_lib.BIO_read(wbio, buf, tonumber(pending))
      if n > 0 then tcp:write(ffi.string(buf, n)) end
      pending = ssl_lib.BIO_ctrl_pending(wbio)
    end
  end

  -- ── Adapter object ────────────────────────────────────────────────────────
  local adapter = { _ssl = ssl, _tcp = tcp, _closed = false }

  function adapter:write(data)
    if self._closed then return end
    ssl_lib.SSL_write(self._ssl, data, #data)
    flush_wbio()
  end

  function adapter:read_start(fn)
    tcp:read_start(function(rerr, chunk)
      if self._closed then return end
      if rerr or not chunk then
        fn(rerr or "eof", nil)
        return
      end
      ssl_lib.BIO_write(rbio, chunk, #chunk)
      local outbuf = ffi.new("char[65536]")
      while true do
        local n = ssl_lib.SSL_read(self._ssl, outbuf, 65536)
        if n <= 0 then break end
        fn(nil, ffi.string(outbuf, n))
      end
    end)
  end

  function adapter:read_stop()
    tcp:read_stop()
  end

  function adapter:is_closing()
    return tcp:is_closing()
  end

  function adapter:close()
    if self._closed then return end
    self._closed = true
    ssl_lib.SSL_free(self._ssl) -- also frees the BIOs (owned by SSL)
    if not tcp:is_closing() then tcp:close() end
  end

  -- ── Async TLS handshake ───────────────────────────────────────────────────
  local hs_done = false

  local function pump()
    flush_wbio()
    local ret = ssl_lib.SSL_do_handshake(ssl)
    flush_wbio()
    if ret == 1 then
      hs_done = true
      tcp:read_stop()
      callback(nil, adapter)
      return
    end
    local e = ssl_lib.SSL_get_error(ssl, ret)
    if e == _SSL_ERROR_WANT_READ then
      -- waiting for server data — libuv will call us back via read_start
    elseif e == _SSL_ERROR_WANT_WRITE then
      pump() -- already flushed; retry immediately
    else
      tcp:read_stop()
      ssl_lib.SSL_free(ssl)
      callback("TLS handshake failed: SSL_get_error=" .. e)
    end
  end

  tcp:read_start(function(rerr, data)
    if hs_done then return end
    if rerr or not data then
      ssl_lib.SSL_free(ssl)
      callback("TLS handshake TCP error: " .. tostring(rerr))
      return
    end
    ssl_lib.BIO_write(rbio, data, #data)
    pump()
  end)

  pump() -- ClientHello: sends TLS records before the server responds
end

return M
