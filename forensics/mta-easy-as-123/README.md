# Malware-Traffic-Analysis — "Easy As 123" (2026-02-28)

> **Category:** network forensics / incident response
> **Source:** [malware-traffic-analysis.net training exercise](https://www.malware-traffic-analysis.net/2026/02/28/index.html) (public training pcap)
> **Tools:** Python 3 + Scapy (no Wireshark — full CLI workflow)
> **Environment:** authorized training dataset

## Scenario

A SOC SIEM fires on **NetSupport Manager RAT** signatures for `45.131.214.85`
over TCP/443, first seen 2026-02-28 19:55 UTC. We get the pcap captured on
the victim host and must produce the incident report:

1. IP address of the infected Windows client
2. Its MAC address
3. Its host name
4. The Windows user account name
5. The full name of that user

Environment: LAN `10.2.28.0/24`, AD domain `easyas123.tech` (`EASYAS123`),
DC at `10.2.28.2` (`EASYAS123-DC`), gateway `10.2.28.1`.

## Step 1 — Pivot on the C2 indicator

Everything starts from the one IOC we have. Which internal host talks to
`45.131.214.85`?

```python
from scapy.all import rdpcap, IP, Ether

pkts = rdpcap("2026-02-28-traffic-analysis-exercise.pcap")
C2 = "45.131.214.85"
hits = [p for p in pkts if IP in p and (p[IP].src == C2 or p[IP].dst == C2)]
hosts = {p[IP].src: p[Ether].src for p in hits if p[IP].dst == C2}
print(hosts)
```

```
total packets: 15512
C2-related packets: 550
{'10.2.28.88': '00:19:d1:b2:4d:ad'}
first: 2026-02-28 19:55:51 UTC   <- matches the SIEM timestamp
```

**Q1 → IP `10.2.28.88`** · **Q2 → MAC `00:19:d1:b2:4d:ad`**

Note the C2 is contacted by raw IP — no DNS lookup for it exists in the
capture. The host's DNS is pure Windows noise (`wpad.*`, MS telemetry),
which is typical for NetSupport: the operator connects straight to the
configured address.

## Step 2 — Host name from Kerberos

In an AD environment the fastest hostname source is Kerberos itself: service
tickets embed the target SPN. String-mining port-88 payloads:

```
'DESKTOP-TEYQ2NR '
'desktop-teyq2nr.easyas123.tech'     <- host/ SPN for our client
'EASYAS123-DC.easyas123.tech'
```

(NBNS registration traffic shows the same name — `nbns` in Wireshark terms.)

**Q3 → host name `DESKTOP-TEYQ2NR`**

## Step 3 — User account from Kerberos CNameString

AS-REQ/TGS-REQ packets carry the client principal in cleartext. Wireshark
calls the field `kerberos.CNameString`; with Scapy it falls out of the same
string pass:

```
'EASYAS123.TECH' | 'brolf' | 'krbtgt' | ...
```

`brolf` appears as the cname across AS-REQ and TGS-REQ exchanges from
10.2.28.88.

**Q4 → user account `brolf`**

## Step 4 — Full name: the UTF-16 trap

The account looks like first-initial + last name (`b` + `rolf`). Hunting for
the display name with a naive ASCII grep finds **nothing**:

```
b"Rolf" in payload        -> 0 hits
"Rolf" in UTF-16-LE ...   -> 1 hit, SMB (TCP 445)
```

Windows SMB carries identity strings in UTF-16-LE, which defeats plain
`strings` and case-sensitive packet searches. Scanning every frame's raw
bytes for the UTF-16 pattern:

```python
pat = "Rolf".encode("utf-16-le")
for i, p in enumerate(pkts):
    raw = bytes(p)
    j = raw.find(pat)
    if j >= 0:
        print(i, raw[j-160:j+64].decode("utf-16-le", errors="replace"))
```

```
--- pkt 338  TCP:445>59988  (DC -> client, session setup / account info)
'...brolf\x00\x00\x00...Becka Rolf\x00\x00\x00...'
```

The DC's reply pairs the sAMAccountName (`brolf`) with the account's display
name.

**Q5 → full name `Becka Rolf`**

## Incident report

| Field | Value | Evidence |
|---|---|---|
| Infected client IP | `10.2.28.88` | 550 frames with C2 `45.131.214.85` |
| MAC | `00:19:d1:b2:4d:ad` | Ethernet src on C2-bound frames |
| Host name | `DESKTOP-TEYQ2NR` | Kerberos SPN / NBNS |
| User account | `brolf` | `kerberos.CNameString` |
| Full name | `Becka Rolf` | SMB session info, UTF-16-LE |
| C2 | `45.131.214.85:443` | active 19:55:51 UTC 02-28 → 00:16 UTC 03-01 |
| Malware | NetSupport Manager RAT | SIEM signature + matching traffic |

**Recommended actions:** isolate `DESKTOP-TEYQ2NR`, reset credentials for
`brolf` (Kerberos tickets were active during compromise), block
`45.131.214.85` egress, and hunt the fleet for the same destination IP.

## Takeaways

- One network IOC → full host/user attribution using only AD chatter that is
  *already in the air*: Kerberos principals, NBNS names, SMB session data.
- The single most useful habit: **try UTF-16-LE when ASCII search fails** on
  Windows protocol traffic. Half of host attribution hides there.
- Scapy is a perfectly serviceable Wireshark substitute for scripted triage —
  the whole analysis above is ~40 lines of Python (see `analyze.py`).
