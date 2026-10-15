# nmap-ics-audit-scripts

Two Nmap NSE scripts that **enhance the built-in `modbus-discover` script** into
unauthenticated-exposure auditors for operational-technology services. The
built-in `modbus-discover` only enumerates Modbus slave ids and their device
information; these enhancements turn that idea into scored audits and extend it
to a second protocol (a FIX trading gateway).

Created for the Cyber Security course, Fall Semester 2026-2027, SCOPE,
VIT Chennai.

> All register reads and FIX admin messages are non-destructive. The only write
> ever attempted is a single Modbus coil write that a secure gateway is expected
> to reject; it exists purely to prove whether writes are blocked. Run these
> only against systems you own or are authorised to test.

## Scripts

| File | Based on | What it does |
|------|----------|--------------|
| `modbus-exposure-audit.nse` | `modbus-discover` (built-in) | Keeps the device fingerprint, adds an unauthenticated register-read and a write-rejection check, reports PASS/FAIL findings and scores exposure LOW/MEDIUM/HIGH (0-6). |
| `fix-gateway-audit.nse` | `modbus-discover` (technique reused) | Applies the same exposure-audit idea to a FIX gateway: plaintext Logon, EncryptMethod echo and skipped-MsgSeqNum checks, scored LOW/MEDIUM/HIGH (0-6). |

## Usage

```bash
# Reference (built-in) script these enhance:
nmap -p 502 --script modbus-discover <target>

# Enhancement 1 - Modbus exposure audit
nmap -p 502 --script ./modbus-exposure-audit.nse <target>
nmap -p 502 --script ./modbus-exposure-audit.nse \
  --script-args modbus-audit.unit=1 <target>

# Enhancement 2 - FIX gateway audit
nmap -p 9878 --script ./fix-gateway-audit.nse <target>
nmap -p 9878 --script ./fix-gateway-audit.nse \
  --script-args fix-audit.sender=AUDIT,fix-audit.target=GATEWAY <target>
```

To install into Nmap's script directory instead of running by path:

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

S Sharvesh

## Acknowledgement

Course offered by SCOPE, VIT Chennai. Faculty: Dr. T. Subbulakshmi,
Professor, SCOPE, VIT Chennai. Nmap by Gordon Lyon (Fyodor); the built-in
`modbus-discover` script by Alexander Rudakov. Modbus specification by the
Modbus Organization; FIX protocol by the FIX Trading Community.
