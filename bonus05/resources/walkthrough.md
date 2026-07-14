# bonus05 — walkthrough

**Binary:** `/home/bonus05/environ` (SUID `flagbonus05`) — **no source**
**Goal:** read `/home/flagbonus05/.pass`

## Recon
```
PIE (ASLR off), NX, canary. info_leak() prints environ (a stack addr) and the
vault (PIE base). No setreuid in main.
main: trace_query(); handle_input();
```

## Bugs (same recipe as level09)
* `trace_query`: `fgets(buf,0x40); ...; printf(buf);` → format string, leaks the
  **canary** at `%15$`.
* `handle_input`: `gets(buf@rbp-0x60)` → overflow, `buf[0x58]` is the canary
  (**offset 88**).

## Exploit
1. `trace_query`: send `%15$p` → canary.
2. `handle_input`: `['A'*88][canary]['A'*8][ret2libc]` (a non GET/SET command
   just returns → chain runs).
3. chain: `setreuid(1032,1032)` + `system("/bin/sh")` (movaps-aligned), command
   fed on stdin.

(The environ/vault leaks would matter under ASLR; here they're confirmation.)

## Run
```
python3 exploit.py   ->   nvazef2rudbey6zmn8pe6kqzpjufcigw
```

**flagbonus05 = `nvazef2rudbey6zmn8pe6kqzpjufcigw`** (final flag — end of the bonus track)
