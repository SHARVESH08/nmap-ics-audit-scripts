local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhancement 2 of the built-in Nmap script modbus-discover - the same
unauthenticated-exposure audit idea applied to a second operational protocol,
a FIX trading gateway.

Runs three FIX session-security checks (plaintext Logon, EncryptMethod echo,
skipped-MsgSeqNum tolerance) and turns them into a scored GATEWAY AUDIT:

  * Each check becomes a PASS/FAIL finding with a short explanation.
  * The gateway's advertised FIX version and SenderCompID (if echoed) are
    extracted and shown.
  * A weighted RISK SCORE (0-6) maps to LOW / MEDIUM / HIGH.
  * Script arguments set the SenderCompID and TargetCompID used in the probes.

Only Logon and Heartbeat admin messages are sent; no orders are ever placed.
]]

---
-- @usage
-- nmap -p 9878 --script fix-gateway-audit <target>
-- nmap -p 9878 --script fix-gateway-audit --script-args fix-audit.sender=AUDIT,fix-audit.target=GATEWAY <target>
--
-- @args fix-audit.sender  SenderCompID (49) to use. Default: AUDIT.
-- @args fix-audit.target  TargetCompID (56) to use. Default: GATEWAY.

author = "Sharvesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

portrule = shortport.port_or_service({443, 9878}, {"https", "kca-service"}, "tcp")

local SOH = string.char(0x01)
local BEGINSTRING = "FIX.4.2"

local function fix_message(body_fields)
  local body = table.concat(body_fields, SOH) .. SOH
  local header = "9=" .. #body .. SOH
  local msg = "8=" .. BEGINSTRING .. SOH .. header .. body
  local sum = 0
  for i = 1, #msg do sum = sum + msg:byte(i) end
  return msg .. string.format("10=%03d", sum % 256) .. SOH
end

local function tagval(buf, tag)
  if not buf then return nil end
  return buf:match(SOH .. tag .. "=([^" .. SOH .. "]+)")
      or buf:match("^" .. tag .. "=([^" .. SOH .. "]+)")
end

action = function(host, port)
  local sender = stdnse.get_script_args("fix-audit.sender") or "AUDIT"
  local target = stdnse.get_script_args("fix-audit.target") or "GATEWAY"
  local out = stdnse.output_table()
  local findings = {}
  local score = 0

  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  if not sock:connect(host, port) then sock:close(); return nil end

  -- Check 1+2: plaintext Logon (weight 3) and EncryptMethod echo (weight 1)
  sock:send(fix_message({
    "35=A", "49=" .. sender, "56=" .. target, "34=1",
    "52=20260724-12:24:00", "98=0", "108=30"
  }))
  local st, resp = sock:receive_bytes(1)
  local logon_type = st and tagval(resp, "35") or nil

  if logon_type == "A" then
    table.insert(findings, "FAIL  Logon accepted with EncryptMethod=None - unauthenticated plaintext session (+3)")
    score = score + 3
    local ver = tagval(resp, "8");  if ver then out["fix_version"] = ver end
    local scid = tagval(resp, "49"); if scid then out["gateway_compid"] = scid end
    if tagval(resp, "98") == "0" then
      table.insert(findings, "FAIL  Gateway echoed EncryptMethod=0 - session confirmed plaintext (+1)")
      score = score + 1
    end

    -- Check 3: skipped MsgSeqNum (weight 2)
    sock:send(fix_message({
      "35=0", "49=" .. sender, "56=" .. target, "34=5",
      "52=20260724-12:24:05"
    }))
    local st2, r2 = sock:receive_bytes(1)
    local mt = st2 and tagval(r2, "35") or nil
    if not st2 or (mt ~= "3" and mt ~= "2" and mt ~= "5") then
      table.insert(findings, "FAIL  Skipped MsgSeqNum was not challenged - sequence integrity not enforced (+2)")
      score = score + 2
    else
      table.insert(findings, "PASS  Skipped MsgSeqNum was challenged (Reject/ResendRequest/Logout)")
    end
  else
    table.insert(findings, "PASS  Gateway refused the plaintext Logon")
  end

  sock:close()

  out["findings"] = findings
  local rating
  if score == 0 then rating = "LOW"
  elseif score <= 3 then rating = "MEDIUM"
  else rating = "HIGH" end
  out["risk_score"] = score .. "/6"
  out["rating"] = rating
  return out
end
