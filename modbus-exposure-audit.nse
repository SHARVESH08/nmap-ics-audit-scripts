local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enhancement 1 of the built-in Nmap script modbus-discover.

Where modbus-discover only enumerates Modbus slave/unit ids and reads their
device-identification strings, this script keeps that fingerprinting and adds
two more safe probes (an unauthenticated Read Holding Registers and a single
write-rejection check) and turns the whole thing into a full EXPOSURE AUDIT:

  * Each probe is recorded as a PASS/FAIL finding with a short explanation.
  * The returned vendor / product / firmware strings are extracted and shown,
    so the operator sees exactly what an attacker could fingerprint.
  * A weighted EXPOSURE SCORE (0-6) is computed from the findings and mapped
    to a LOW / MEDIUM / HIGH rating for quick triage.
  * An optional script argument sets the Modbus unit id to probe.

Only coil 0 is ever written, and only to observe whether the write is
blocked; a secure gateway rejects it. All register access is read-only.
]]

---
-- @usage
-- nmap -p 502 --script modbus-exposure-audit <target>
-- nmap -p 502 --script modbus-exposure-audit --script-args modbus-audit.unit=1 <target>
--
-- @args modbus-audit.unit  Modbus unit/slave id to probe. Default: 1.

author = "Sharvesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

portrule = shortport.port_or_service(502, "mbap", "tcp")

local function adu(txn, unit, pdu)
  local length = #pdu + 1
  return string.pack(">I2 I2 I2 B", txn, 0, length, unit) .. pdu
end

local function transact(host, port, txn, unit, pdu)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  if not sock:connect(host, port) then sock:close(); return nil end
  sock:send(adu(txn, unit, pdu))
  local status, resp = sock:receive_bytes(9)
  sock:close()
  if not status or #resp < 8 then return nil end
  return resp:sub(8)
end

-- Pull the printable vendor/product/firmware objects out of a 0x2B/0x0E reply.
local function parse_device_id(pdu)
  -- layout: 2B 0E <devid code> <conformity> <more> <next> <obj count> then
  -- repeating [obj id][len][value]
  if #pdu < 7 then return nil end
  local n = pdu:byte(7)
  local pos = 8
  local fields = {}
  for _ = 1, n do
    if pos + 1 > #pdu then break end
    local len = pdu:byte(pos + 1)
    local value = pdu:sub(pos + 2, pos + 1 + len)
    table.insert(fields, value)
    pos = pos + 2 + len
  end
  if #fields == 0 then return nil end
  return table.concat(fields, " / ")
end

action = function(host, port)
  local unit = tonumber(stdnse.get_script_args("modbus-audit.unit")) or 1
  local out = stdnse.output_table()
  local findings = {}
  local score = 0

  -- Probe 1: Read Holding Registers (weight 3)
  local r1 = transact(host, port, 1, unit, string.pack(">B I2 I2", 0x03, 0, 1))
  if r1 and r1:byte(1) == 0x03 then
    table.insert(findings, "FAIL  Unauthenticated Read Holding Registers - register data returned with no login (+3)")
    score = score + 3
  else
    table.insert(findings, "PASS  Read Holding Registers was refused or unanswered")
  end

  -- Probe 2: Read Device Identification (weight 2)
  local r2 = transact(host, port, 2, unit, string.pack(">B B B B", 0x2B, 0x0E, 0x01, 0x00))
  if r2 and r2:byte(1) == 0x2B then
    local id = parse_device_id(r2)
    table.insert(findings, "FAIL  Unauthenticated Read Device Identification - firmware fingerprint exposed (+2)")
    if id then out["device_fingerprint"] = id end
    score = score + 2
  else
    table.insert(findings, "PASS  Read Device Identification was refused or unanswered")
  end

  -- Probe 3: Write Single Coil (weight 1 if ACCEPTED - that would be unsafe)
  local r3 = transact(host, port, 3, unit, string.pack(">B I2 I2", 0x05, 0, 0xFF00))
  if r3 and r3:byte(1) == (0x05 + 0x80) then
    table.insert(findings, "PASS  Write Single Coil was rejected with a Modbus exception - writes are blocked")
  elseif r3 and r3:byte(1) == 0x05 then
    table.insert(findings, "FAIL  Write Single Coil was ACCEPTED - the device allows unauthenticated writes (+1)")
    score = score + 1
  else
    table.insert(findings, "WARN  Write Single Coil got no clear response")
  end

  out["unit_id"] = unit
  out["findings"] = findings

  local rating
  if score == 0 then rating = "LOW"
  elseif score <= 3 then rating = "MEDIUM"
  else rating = "HIGH" end

  out["exposure_score"] = score .. "/6"
  out["rating"] = rating
  return out
end
