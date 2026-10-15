# nmap-ics-audit-scripts

Four Nmap NSE scripts that audit two operational-technology protocols for
**unauthenticated exposure**: Modbus/TCP (industrial control systems) and FIX
(financial trading gateways). The project starts from a minimal Modbus
detection script and enhances the same "can an attacker act without logging
in?" technique into a scored Modbus exposure audit and then into a second
protocol (FIX) gateway audit.

Created for the Cyber Security course, Fall Semester 2026-2027, SCOPE,
VIT Chennai.

> All register reads and FIX admin messages are non-destructive. The only
> write ever attempted is a single Modbus coil write that a secure gateway is
> expected to reject; it exists purely to prove whether writes are blocked.
> Run these only against systems you own or are authorised to test.

## Scripts

| File | Role | What it does |
|------|------|--------------|
| `modbus-detect.nse` | Reference | Confirms unauthenticated Read Holding Registers + Read Device ID, and that a Write Single Coil is rejected. |
| `modbus-exposure-audit.nse` | Enhancement 1 | Same probes as PASS/FAIL findings, extracts the device fingerprint, and scores exposure LOW/MEDIUM/HIGH (0-6). |
| `fix-detect.nse` | Reference (2nd protocol) | Detects a FIX gateway accepting a plaintext Logon and tolerating a skipped MsgSeqNum. |
| `fix-gateway-audit.nse` | Enhancement 2 | Turns the FIX checks into scored PASS/FAIL findings with a LOW/MEDIUM/HIGH risk rating (0-6). |

## Usage

```bash
# Reference - Modbus detection
nmap -p 502 --script ./modbus-detect.nse <target>

# Enhancement 1 - Modbus exposure audit (optional unit id)
nmap -p 502 --script ./modbus-exposure-audit.nse <target>
nmap -p 502 --script ./modbus-exposure-audit.nse \
  --script-args modbus-audit.unit=1 <target>

# Reference - FIX gateway detection
nmap -p 9878 --script ./fix-detect.nse <target>

# Enhancement 2 - FIX gateway audit (optional comp ids)
nmap -p 9878 --script ./fix-gateway-audit.nse <target>
nmap -p 9878 --script ./fix-gateway-audit.nse \
  --script-args fix-audit.sender=AUDIT,fix-audit.target=GATEWAY <target>
```

To install into Nmap's script directory instead of running by path, copy the
files there and refresh the script database:

```bash
sudo cp *.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
```

## Scoring

**Modbus exposure (max 6):** unauthenticated register read = 3,
device-id fingerprint = 2, accepted unauthenticated write = 1.

**FIX gateway risk (max 6):** plaintext Logon accepted = 3,
skipped MsgSeqNum tolerated = 2, EncryptMethod=0 echoed = 1.

Score 0 = LOW, 1-3 = MEDIUM, 4-6 = HIGH.

## Author

[Your Name]

## Acknowledgement

Course offered by SCOPE, VIT Chennai. Faculty: Dr. T. Subbulakshmi,
Professor, SCOPE, VIT Chennai. Nmap by Gordon Lyon (Fyodor). Modbus
specification by Modbus Organization; FIX protocol by the FIX Trading
Community.
