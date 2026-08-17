# MemLabs Lab 1 — "Beginner's Luck" memory forensics

> **Category:** digital forensics / memory analysis
> **Dataset:** [MemLabs Lab 1](https://github.com/stuxnet999/MemLabs) (`MemoryDump_Lab1.raw`, md5 `b9fec1a443907d870cb32b048bda9380`)
> **Scenario:** "My sister's computer crashed. We recovered this memory dump. She suddenly saw a black window pop up with something being executed. When the crash happened, she was trying to draw something."
> **Tools:** Volatility 3, Python (custom Mega.nz downloader, custom DIB carving), strings
> **Environment:** authorized public training dataset

## 0. Getting the image without a browser

The dataset ships as a 7-zip archive behind a Mega.nz public link. Instead of
the browser, I scripted the whole fetch: Mega's `g.api.mega.co.nz/cs` endpoint
returns the CDN URL for a public handle, and the payload decrypts with
AES-128-CTR using a key folded out of the 32-byte link fragment
(`k[i] ^ k[i+16]` u32-folding, 8-byte CTR prefix IV). Verified end-to-end:
the downloaded archive's MD5 (`919a0ded...`) matches the challenge page, and
the inner dump matches too (`b9fec1a4...`).

## 1. Image identification

```
$ vol -q -f MemoryDump_Lab1.raw windows.info
Kernel Base     0xf8000261f000
DTB             0x187000
Is64Bit         True
NTBuildLab      7601.17514.amd64fre.win7sp1_rtm.
Major/Minor     15.7601
SystemTime      2019-12-11 14:38:00+00:00
```

Windows 7 SP1 x64, captured 2019-12-11 14:38 UTC. (Volatility 3 pulled the
`ntkrnlmp.pdb` ISF for build `3844DBB9...` itself; on a locked-down network
you'd pre-stage that symbol file.)

## 2. Process timeline (pslist)

Filtering the noise, the user-session story reconstructs itself:

```
PID    PPID  Image          Session  CreateTime
604    2016  explorer.exe   1        14:32:25   <- interactive desktop
1984   604   cmd.exe        1        14:34:54   <- "black window"
2692   368   conhost.exe    1        14:34:54
2424   604   mspaint.exe    1        14:35:14   <- the drawing
1512   2504  WinRAR.exe     2        14:37:23   <- a second user session
796    604   DumpIt.exe     1        14:37:54   <- memory capture
```

`cmd.exe` out of `explorer.exe`, three and a half minutes before `DumpIt.exe`
froze the machine — consistent with the witness story.

## 3. What ran in the black window

`windows.cmdline` gives bare `cmd.exe` (no arguments), so the answer lives in
the console memory. Two independent artifacts agree:

- `strings -e l` over the image: window title `C:\Windows\system32\cmd.exe - St4G3$1`
- process dump of PID 1984: same title, working dir `C:\Users\SmartNet`, `ECHO OFF` (batch context)

And a raw `strings` pass over the image shows the supporting cast on the
desktop:

```
C:\Users\SmartNet\Desktop\St4G3$1.bat
SmartNet\Desktop\St4g3$1.txt
SmartNet\Desktop\st4G3$$1.txt
St4G3$1.bat.lnk
```

A batch file `St4G3$1.bat` on the desktop, plus two text files. The console
title carries the stage name — that is the executed-payload evidence.

## 4. The second user & the "important" archive

`cmdline` on the session-2 process:

```
1512  WinRAR.exe  "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Alissa Simpson\Documents\Important.rar"
```

A second user (`Alissa Simpson`) had opened `Important.rar` from her
Documents. `windows.filescan` shows three `_FILE_OBJECT`s for it, but
`windows.dumpfiles` on all three returns nothing: **the archive's bytes were
not resident in memory** — the object records the open, not the content. A
good reminder that a RAM image is a *cache*, not a disk; un-cached file
content is simply not in it.

## 5. Browser history fallout

Firefox had just been installed on this box — proven by a ROT13'd uninstall
string sitting in the image:

```
P:\Hfref\FznegArg\Qbjaybnqf\Sversbk Vafgnyyre.rkr
   --ROT13-->  C:\Users\SmartNet\Downloads\Firefox Installer.exe
```

and its history already records the two text files being opened:

```
Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/St4g3$1.txt
Visited: SmartNet@file:///C:/Users/SmartNet/Desktop/st4G3$$1.txt
```

## 6. The drawing (mspaint, PID 2424)

`windows.memmap --pid 2424 --dump` exports the process. The canvas buffer is
locatable as a ~2.1 MB `0xFF`-filled region (white background), but it is
almost entirely blank: she had *just* started drawing when the dump hit. The
resident canvas contains only a handful of dark pixels — no readable content
is recoverable from this capture. (Documented here because "the drawing
recovered nothing" is itself a legitimate negative finding: the narrative
said she *was trying to* draw, and the memory agrees she barely did.)

## Evidence chain

| Witness claim | Memory evidence |
|---|---|
| "black window popped up and executed something" | `cmd.exe` (PID 1984) 14:34:54, console title `…cmd.exe - St4G3$1`, batch context (`ECHO OFF`), `St4G3$1.bat` on desktop |
| "she was trying to draw" | `mspaint.exe` (PID 2424) 14:35:14, canvas buffer resident but ~blank |
| "important files" | `Important.rar` opened by WinRAR in Alissa Simpson's session; file objects present, content not cached |

## Methodology notes

- **Two independent sources per claim.** Process lists + raw strings +
  console memory all cross-checked before calling anything a finding.
- **Negative results are findings.** "The RAR content is not in the dump"
  tells you the acquisition scope, and matters for what you promise a client.
- **Carving is a lottery.** The DIB/PNG carving passes recovered Windows
  icons and thumbnails but no case-relevant imagery; when the content was
  never paged in, no carver will invent it.
- **Reproducibility:** every output above comes from the commands shown;
  image MD5 verified against the challenge page before analysis began.
