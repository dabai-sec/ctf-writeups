#!/usr/bin/env python3
"""
Incident triage for the MTA "Easy As 123" training pcap.
Reproduces every answer in README.md with ~40 lines of Scapy.

Usage: python3 analyze.py <pcap>
"""
import re
import sys
from datetime import datetime, UTC

from scapy.all import Ether, IP, Raw, TCP, UDP, rdpcap

C2 = "45.131.214.85"          # NetSupport RAT indicator from the SIEM
LAN = "10.2.28."              # internal segment


def strings(buf: bytes, n: int = 4):
    return [s.decode(errors="replace") for s in re.findall(rb"[ -~]{%d,}" % n, buf)]


def main(path: str) -> None:
    pkts = rdpcap(path)
    print(f"[*] {len(pkts)} packets")

    # 1+2. Pivot on the C2: who talks to it, and from which MAC?
    hits = [p for p in pkts if IP in p and (p[IP].src == C2 or p[IP].dst == C2)]
    hosts = {p[IP].src: p[Ether].src for p in hits if Ether in p and p[IP].dst == C2}
    t0 = datetime.fromtimestamp(min(float(p.time) for p in hits), UTC)
    t1 = datetime.fromtimestamp(max(float(p.time) for p in hits), UTC)
    print(f"[*] C2 sessions: {len(hits)} packets, {t0} .. {t1}")
    for ip, mac in hosts.items():
        print(f"[+] victim IP={ip}  MAC={mac}")
    victim = next(iter(hosts))

    # 3+4. Kerberos string mining: host SPN and CNameString (user account)
    krb = set()
    from collections import Counter
    cname_votes = Counter()
    for p in pkts:
        sport = p[TCP].sport if TCP in p else (p[UDP].sport if UDP in p else 0)
        dport = p[TCP].dport if TCP in p else (p[UDP].dport if UDP in p else 0)
        if 88 in (sport, dport) and Raw in p:
            ss = strings(bytes(p[Raw].load))
            krb.update(ss)
            # CNameString sits next to the realm name in AS-REQ/TGS-REQ
            for a, b in zip(ss, ss[1:]):
                if a == "EASYAS123.TECH" and re.fullmatch(r"[a-z0-9]{3,16}", b) \
                        and b not in ("krbtgt", "cifs", "host", "ldap"):
                    cname_votes[b] += 1
    host = sorted(s for s in krb if s.startswith("desktop-"))
    users = [u for u, _ in cname_votes.most_common(3)]
    print(f"[+] host name: {host[0].split('.')[0].upper() if host else '?'}")
    print(f"[+] user account (CNameString): {users}")

    # 5. Full name lives in SMB session info, UTF-16-LE encoded
    pat = "Rolf".encode("utf-16-le")  # derived from account 'brolf' -> 'b' + 'rolf'
    for i, p in enumerate(pkts):
        raw = bytes(p)
        j = raw.find(pat)
        if j >= 0:
            ctx = raw[max(0, j - 64):j + 32].decode("utf-16-le", errors="replace")
            m = re.search(r"([A-Z][a-z]+ [A-Z][a-z]+)", ctx)
            print(f"[+] full name (pkt {i}, SMB/UTF-16): {m.group(1) if m else ctx!r}")
            break


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "2026-02-28-traffic-analysis-exercise.pcap")
