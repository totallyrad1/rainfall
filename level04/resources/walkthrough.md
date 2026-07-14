# level04 — walkthrough

**Binary:** `/home/level04/riviera` (SUID `flag04`, x86-64)
**Goal:** read `/home/flag04/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), No canary, GNU_STACK = RW (NX ON), ASLR off.
```
`display_entry()`:
```c
printf(log_buf[idx].tag);     // format string is fully attacker-controlled
```
`tag` is a `fgets(tag, 32, ...)` field (<=31 bytes), copied into the global
`log_buf`. `message` is `fgets(msg, 256, ...)` into a **stack** local of
`handle_input`.

## 2. The primitive
The format string sits in `.bss`, so we can't place `%n` target addresses next
to it. But `handle_input`'s `msg[]` local is still on the stack when
`display_entry` runs, and it shows up at printf argument **`%10$`**
(`msg[k*8]` == `%(10+k)$`). That gives a classic address-in-buffer + `%n`
**arbitrary write** with only a short format string.

## 3. Why not GOT->system
No call after the format string takes a controlled first argument, and
`/bin/sh` would drop the euid. So we need a real ret2libc chain
(`setreuid(1021,1021)` then `system`). We deliver it with a **frame-pointer
pivot** (level02-style) using a single `%hn`.

## 4. The pivot
Frames at `printf(tag)`:
```
disp_rbp = handle_input_rbp - 0x130   holds handle_input's saved rbp
msg      = handle_input_rbp - 0x120   (== disp_rbp + 0x10)
```
Steps:
1. Put the ret2libc chain in `msg`, and the address `disp_rbp` at `msg[88]`
   (== `%21$`).
2. `%<W>c%21$hn` writes `W = (msg-8) & 0xffff` into the low 2 bytes of
   `[disp_rbp]`, i.e. sets handle_input's saved rbp to `msg-8`.
3. `display_entry`'s `pop rbp` loads it; `handle_input`'s `leave;ret` pivots
   `rsp` to `msg` and runs the chain — **before** `flush_log`, so `msg` is
   still intact.

## 5. Leak-and-go
`handle_input_rbp` shifts a little between runs, so the exploit first leaks it
with `%8$p`, then builds `msg`/`tag` from it — all in one process
(`subprocess`), so the address is consistent. Chain length is chosen so
`system()` enters at `rsp % 16 == 8` (movaps-aligned).

## 6. Run
```
python3 exploit.py
-> x0w8xdgapz3tjopq2s11a27yro7krazm
```

**flag04 = `x0w8xdgapz3tjopq2s11a27yro7krazm`** (SSH password for level05)

## Gotcha
The flag05/flag06 uids are consecutive (flag03=1020, flag04=1021, flag05=1022…);
using the wrong one makes `setreuid` fail with EPERM and `/bin/sh` silently
drops back to the unprivileged uid.
