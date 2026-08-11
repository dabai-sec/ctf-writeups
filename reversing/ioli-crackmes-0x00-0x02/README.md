# IOLI Crackmes 0x00–0x02 — Static Analysis Walkthrough

> **Category:** reverse engineering
> **Targets:** IOLI crackme series (public training set, i386 ELF)
> **Tools:** `strings`, `objdump`, manual logic recovery
> **Environment:** authorized training binaries, local lab

The IOLI set is the "hello world" of reverse engineering: ten tiny binaries,
each hiding a password check. This note covers levels 0x00–0x02 with a
purely static workflow — no debugger, no decompiler, just `strings` and
`objdump`, because that is all you need at this level.

## 0x00 — The plaintext compare

First contact: what does the binary import and what does it carry?

```
$ file crackme0x00
crackme0x00: ELF 32-bit LSB executable, Intel i386, dynamically linked, not stripped

$ strings crackme0x00
printf
strcmp                       <- compare function imported
scanf
IOLI Crackme Level 0x00
Password:
250382                       <- ...that looks like an answer
Invalid Password!
Password OK :)
```

`strcmp` + a suspicious 6-digit constant sitting between the prompt and the
verdict strings. The password is embedded in `.rodata` in cleartext.

**Password: `250382`**

Lesson: before touching a disassembler, *listen to the binary*. `strings`
and the import table alone solve level 0.

## 0x01 — The immediate compare

No cleartext this time. Disassemble `main` (Intel syntax — AT&T is a crime
against readability):

```
$ objdump -d crackme0x01 --disassemble=main -M intel
...
 8048418:  lea    eax,[ebp-0x4]
 804841b:  mov    DWORD PTR [esp+0x4],eax
 804841f:  mov    DWORD PTR [esp],0x804854c
 8048426:  call   804830c <scanf@plt>        ; scanf("%d", &input)
 804842b:  cmp    DWORD PTR [ebp-0x4],0x149a ; input vs 0x149a
 8048432:  je     8048442 <main+0x5e>        ; -> "Password OK"
```

The check is a single integer compare against an immediate:

```
$ python3 -c "print(0x149a)"
5274
```

**Password: `5274`**

Lesson: locate the *input sink* (`scanf`), then follow the variable to the
first `cmp`. One instruction is the whole protection scheme.

## 0x02 — The computed compare

Now the constant is built at runtime. The relevant slice of `main`:

```
 804842b:  mov    DWORD PTR [ebp-0x8],0x5a    ; a = 0x5a   (90)
 8048432:  mov    DWORD PTR [ebp-0xc],0x1ec   ; b = 0x1ec  (492)
 8048439:  mov    edx,DWORD PTR [ebp-0xc]
 804843f:  add    DWORD PTR [eax],edx         ; a += b  -> 90 + 492 = 582
 8048441:  mov    eax,DWORD PTR [ebp-0x8]
 8048444:  imul   eax,DWORD PTR [ebp-0x8]     ; a * a   -> 582^2 = 338724
 8048448:  mov    DWORD PTR [ebp-0xc],eax     ; b = 338724
 804844b:  mov    eax,DWORD PTR [ebp-0x4]
 804844e:  cmp    eax,DWORD PTR [ebp-0xc]     ; input vs 338724
```

Recovered algorithm: `expected = (90 + 492)² = 338724`.

**Password: `338724`**

Lesson: obfuscation here is just arithmetic. Trace the data flow through the
stack slots and recompute by hand — no emulator required for straight-line code.

## Summary

| Level | Protection | Answer | Technique |
|-------|-----------|--------|-----------|
| 0x00 | plaintext in `.rodata` | `250382` | `strings` |
| 0x01 | immediate `cmp` | `5274` | read the `cmp` operand |
| 0x02 | runtime computation | `338724` | data-flow recovery |

The progression is the whole point of the series: each level moves the secret
one step further from static visibility. Levels 0x03+ introduce control-flow
tricks (`shift`/`dummy` env checks), which is where a debugger starts paying
rent — covered in a future note.
