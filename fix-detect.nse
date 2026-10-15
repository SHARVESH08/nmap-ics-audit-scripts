local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Reference script (second protocol family).

Detects an exposed FIX (Financial Information eXchange) trading gateway and
checks three session-security weaknesses using only standard FIX admin
messages:

  1. Sends a Logon (35=A) requesting EncryptMethod=0 (None). A gateway that
     answers with its own Logon is accepting an UNENCRYPTED session.
  2. Confirms the gateway echoes EncryptMethod=0, proving the session really
     is plaintext.
  3. Sends an admin message with a deliberately SKIPPED MsgSeqNum (34). A
     correctly implemented gateway must challenge the gap with a Reject,
     ResendRequest or Logout; silence means sequence integrity is not
     enforced.

No orders are ever sent - only Logon and Heartbeat admin messages. This is
the baseline reference that fix-gateway-audit.nse builds upon.
]]

author = "Sharvesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({443, 9878}, {"https", "kca-service"}, "tcp")

local SOH = string.char(0x01)
local BEGINSTRING = "FIX.4.2"

-- Assemble a FIX message from an ordered list of "tag=value" body fields.
-- Prepends 8=/9= and appends the 10= checksum, all delimited by SOH.
local function fix_message(body_fields)
  local body = table.concat(body_fields, SOH) .. SOH
  local header = "9=" .. #body .. SOH
  local msg = "8=" .. BEGINSTRING .. SOH .. header .. body
  local sum = 0
  for i = 1, #msg do sum = sum + msg:byte(i) end
  return msg .. string.format("10=%03d", sum % 256) .. SOH
end

local function send_recv(host, port, msg)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  if not sock:connect(host, port) then sock:close(); return nil, nil end
  sock:send(msg)
  local status, resp = sock:receive_bytes(1)
  if not status then sock:close(); return sock, nil end
  return sock, resp
end

-- Read FIX tag 35 (MsgType) from a raw buffer.
local function msgtype(buf)
  if not buf then return nil end
  return buf:match(SOH .. "35=([^" .. SOH .. "]+)") or buf:match("^35=([^" .. SOH .. "]+)")
end

action = function(host, port)
  local out = stdnse.output_table()
  local sender, target = "AUDIT", "GATEWAY"

  -- Step 1+2: Logon with EncryptMethod=None (98=0), HeartBtInt=30 (108=30)
  local logon = fix_message({
    "35=A", "49=" .. sender, "56=" .. target, "34=1",
    "52=20260724-12:24:00", "98=0", "108=30"
  })
  local sock, resp = send_recv(host, port, logon)

  if msgtype(resp) == "A" then
    out[#out + 1] = "Logon succeeded with EncryptMethod=None - gateway accepted an unencrypted session"
    if resp:match(SOH .. "98=0" .. SOH) or resp:match("^98=0" .. SOH) then
      out[#out + 1] = "Gateway echoed back EncryptMethod=0, confirming plaintext session"
    end

    -- Step 3: Heartbeat with a skipped MsgSeqNum (jump 2 -> 5)
    local gapped = fix_message({
      "35=0", "49=" .. sender, "56=" .. target, "34=5",
      "52=20260724-12:24:05"
    })
    if sock then
      sock:send(gapped)
      local st, r2 = sock:receive_bytes(1)
      local mt = st and msgtype(r2) or nil
      -- Reject (3), ResendRequest (2) or Logout (5) == gap was challenged.
      if not st or (mt ~= "3" and mt ~= "2" and mt ~= "5") then
        out[#out + 1] = "Gateway accepted a message with a skipped MsgSeqNum without challenging it"
      end
    end
  end

  if sock then sock:close() end
  if #out == 0 then return nil end
  return out
end
