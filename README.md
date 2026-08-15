# ctf-writeups

Security research notes and CTF writeups. Everything here was produced in
authorized environments: public training binaries, lab ranges, and training
pcap datasets. No production systems, no unauthorized targets.

## Index

### Binary exploitation

| Writeup | Skills | Tools |
|---|---|---|
| [ROP Emporium — ret2win (x86_64)](pwn/rop-emporium-ret2win/) | stack overflow, ret2win, glibc movaps stack-alignment gotcha | pwntools, objdump, readelf |
| [ROP Emporium — split (x86_64)](pwn/rop-emporium-split/) | first ROP chain, pop rdi gadget, byte-level gadget hunting | pwntools, objdump |
| [ROP Emporium — write4 (x86_64)](pwn/rop-emporium-write4/) | write-what-where gadget, planting strings via registers | objdump, readelf |
| [ROP Emporium — fluff (x86_64)](pwn/rop-emporium-fluff/) | xlat/bextr/stos gadget set, register-state calibration, byte scavenging | objdump, gdb |

### Reverse engineering

| Writeup | Skills | Tools |
|---|---|---|
| [IOLI crackmes 0x00–0x02](reversing/ioli-crackmes-0x00-0x02/) | static triage, import analysis, data-flow recovery | strings, objdump |

### Network forensics

| Writeup | Skills | Tools |
|---|---|---|
| [MTA "Easy As 123" — NetSupport RAT IR](forensics/mta-easy-as-123/) | C2 pivot, Kerberos/NBNS attribution, UTF-16 string hunting | Scapy |

## Methodology

- **Reproducibility first.** Every writeup ships the exact commands and
  scripts used; outputs in the markdown are real runs, not retellings.
- **Minimal toolchain on purpose.** Where a GUI tool is common practice
  (Wireshark, IDA), the notes show the scriptable equivalent instead.
- **Ethics.** Training targets only. Techniques documented here are for
  defensive work: CTF, incident response, and authorized research.

## Contact

Questions or corrections: open an issue.
