# ROP Emporium — fluff (x86_64)

> **Category:** pwn / binary exploitation
> **Binary:** [fluff](https://ropemporium.com/challenge/fluff.html) (ROP Emporium, x86_64)
> **Techniques:** stack overflow → ROP, exotic gadget set (`xlat` / `bextr` / `stosb`), byte-scavenging from the binary, register state calibration
> **Environment:** authorized training binary, local lab (gdb for tracing)

`fluff` is the series' difficulty spike: no `pop rdx`, no clean
write-what-where. The intended primitive set is three weird instructions,
and the whole solve is learning to think in terms of them.

## 1. Recon

Same layout as the rest of the series: `pwnme()` in `libfluff.so`,
32-byte stack buffer, `read(0, buf, 0x200)`, return address at offset 40.
The only toys we get:

```
0000000000400628 <questionableGadgets>:
  400628:  xlat   [rbx]                 ; ret
  40062a:  pop    rdx
  40062b:  pop    rcx
  40062c:  add    rcx, 0x3ef2
  400633:  bextr  rbx, rcx, rdx         ; ret
  400639:  stos   al, [rdi]             ; ret
```

Three primitives:

| Gadget | Effect |
|---|---|
| `bextr` block | set `rbx` to an arbitrary 64-bit value (with a `+0x3ef2` quirk) |
| `xlat` | `al = [rbx + al]` — a lookup table read |
| `stosb` | `[rdi] = al; rdi++` — a byte writer |

Plan: use `xlat` as a byte-grabber — point `rbx` at a byte inside the
binary whose value is the character we want, load it into `al`, then
`stosb` it into `.bss`. Eight iterations spells `"flag.txt"`.

## 2. The two traps (both verified the hard way)

**Trap 1 — the hidden `+0x3ef2`.** The `bextr` block is not a clean
register load: `add rcx, 0x3ef2` runs between the pop and the extract.
With `rdx = 0x4000` (start=0, length=64) `bextr` passes all 64 bits
through, so `rbx = popped_value + 0x3ef2`. Every address you load must be
pre-compensated: push `target - 0x3ef2`. My first chain forgot this and
dereferenced `0x4042b6` (unmapped) — SIGSEGV on the first `xlat`, found in
seconds with a gdb trace:

```
xlat: rbx=0x600f8b al=0xb        <- calibration step, fine
xlat: rbx=0x4042b6 al=0          <- char 'f': A+0x3ef2, off by ADJ. boom.
```

**Trap 2 — `al` is not yours at the start.** `xlat` computes
`[rbx + al]`, and `al` at chain entry is whatever `pwnme`'s last libc call
left in it. Here that's `puts("Thank you!")`, which returns **11** — so
`al = 0x0b`, and every lookup is skewed by 11 unless you correct for it.
Rather than trusting that number (it is libc-dependent), calibrate: point
`rbx` at a long run of zero bytes in mapped memory (`0x600f8b`, 118 zero
bytes — confirmed via `readelf -l` segment math). Then
`al = [ZERORUN + al] = 0` for *any* starting `al` below 118, no guesses.

After calibration, each character is:

```
rbx = A_char - al_prev      (via bextr, pre-compensated for +0x3ef2)
xlat                        al = [rbx + al_prev] = the character
stosb                       write it, rdi++
```

Byte sources: every character of `flag.txt` exists somewhere in the
read-only LOAD segment (`0x400000–0x400838`); the exploit just scans the
file image for the first occurrence of each byte.

## 3. Run

```
$ python3 exploit.py
fluff by ROP Emporium
x86_64
You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

(The trailing SIGSEGV afterwards is just the chain ending with no clean
exit — the flag is already out.)

Flag: `ROPE{a_placeholder_32byte_flag!}`.

## Takeaway

Exotic-gadget ROP is bookkeeping. The two things that actually bite are
never the gadgets themselves but the **side effects** (`add rcx,0x3ef2`
buried mid-gadget) and the **inherited state** (`al` from the last libc
call). A five-line gdb breakpoint script turns both from guesswork into
printed facts.
