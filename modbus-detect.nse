local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Reference script.

Detects an exposed Modbus/TCP service (port 502) and checks, with three
minimal and safe probes, whether the device answers industrial requests
WITHOUT any authentication:

  1. Read Holding Registers  (function code 0x03)   - a read probe.
  2. Read Device Identification (function 0x2B / MEI 0x0E) - a fingerprint probe.
  3. Write Single Coil       (function code 0x05)   - a single, harmless
     write probe that a safe demo gateway is expected to REJECT.

Reads are non-destructive. The one write probe targets coil 0 and exists only
to show whether the gateway blocks writes; a secure device rejects it with a
Modbus exception. This is the baseline reference that the two enhancements
build upon.
]]

author = "Sharvesh"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(502, "mbap", "tcp")

-- Build a Modbus/TCP ADU: MBAP header (txn, proto=0, len, unit) + PDU.
local function adu(txn, unit, pdu)
  local length = #pdu + 1                      -- unit id + PDU bytes
  return string.pack(">I2 I2 I2 B", txn, 0, length, unit) .. pdu
end

-- Send one ADU and return the PDU of the response (function code + data).
local function transact(host, port, txn, unit, pdu)
  local sock = nmap.new_socket()
  sock:set_timeout(4000)
  local ok = sock:connect(host, port)
  if not ok then sock:close(); return nil end
  sock:send(adu(txn, unit, pdu))
  local status, resp = sock:receive_bytes(9)
  sock:close()
  if not status or #resp < 8 then return nil end
  return resp:sub(8)                            -- strip 7-byte MBAP header
end

action = function(host, port)
  local out = stdnse.output_table()
  local unit = 1

  -- Probe 1: Read Holding Registers, start 0, qty 1  -> PDU 03 0000 0001
  local r1 = transact(host, port, 1, unit, string.pack(">B I2 I2", 0x03, 0, 1))
  if r1 and r1:byte(1) == 0x03 then
    out[#out + 1] = "Read Holding Registers succeeded - device returned register data with no login required"
  end

  -- Probe 2: Read Device Identification -> PDU 2B 0E 01 00
  local r2 = transact(host, port, 2, unit, string.pack(">B B B B", 0x2B, 0x0E, 0x01, 0x00))
  if r2 and r2:byte(1) == 0x2B then
    out[#out + 1] = "Read Device Identification succeeded - vendor/product/firmware strings were returned with no login required"
  end

  -- Probe 3: Write Single Coil, coil 0 = ON (0xFF00) -> PDU 05 0000 FF00
  local r3 = transact(host, port, 3, unit, string.pack(">B I2 I2", 0x05, 0, 0xFF00))
  if r3 and r3:byte(1) == (0x05 + 0x80) then
    out[#out + 1] = "Write Single Coil was rejected with a Modbus exception"
  end

  if #out == 0 then return nil end
  return out
end
