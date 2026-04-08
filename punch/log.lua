-- punch/log.lua
-- Debug logger: writes timestamped lines to a file when debug mode is active.
--
-- Controlled by config.debug (bool) and config.debug_log (file path).
-- Default log path: /tmp/punch.log
--
-- Usage:
--   local log = require("punch.log")
--   log.init(config)          -- call once from session.new()
--   log.debug("probe: %s:%d", addr, port)
--   log.close()               -- optional; called automatically on process exit
local M = {}

M.enabled = false
M._file   = nil

-- Initialise the logger from a session config table.
-- Safe to call multiple times; re-opens the file if the path changes.
function M.init(config)
  config = config or {}
  if not config.debug then
    M.enabled = false
    return
  end

  M.enabled = true
  local path = config.debug_log or "/tmp/punch.log"

  if M._file then
    pcall(function() M._file:close() end)
  end

  local f, err = io.open(path, "a")
  if f then
    M._file = f
  else
    M._file   = nil
    M.enabled = false
    -- Last-resort: print to stderr so the failure is not silent.
    io.stderr:write("[punch] cannot open log file '" .. path .. "': " .. tostring(err) .. "\n")
  end
end

-- Write a formatted debug line.  No-op when debug is disabled.
function M.debug(fmt, ...)
  if not M.enabled or not M._file then return end
  local ok, msg = pcall(string.format, fmt, ...)
  if not ok then msg = fmt end
  M._file:write(os.date("%H:%M:%S") .. " [punch] " .. msg .. "\n")
  M._file:flush()
end

-- Close the log file handle (idempotent).
function M.close()
  if M._file then
    pcall(function() M._file:close() end)
    M._file = nil
  end
  M.enabled = false
end

return M
