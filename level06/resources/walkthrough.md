# level06 — walkthrough

**Binary:** `/home/level06/3jane` (SUID `flag06`, x86-64) — **no source, reversed**
**Goal:** read `/home/flag06/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), NX ON, **stack canary** (new!), ASLR off.
main: init_vault(); print_banner(); log_request(); authenticate(); display_vault();
```
`init_vault` fills the global `vault` with ALPHA/BETA/GAMMA/DELTA entries — **not
the flag** — so `display_vault` never leaks it. We need real code execution.

## 2. Two bugs
* `log_request`: `fgets(buf,0x40); ...; printf(buf);` — **format string** (no
  args passed), so `%N$p` leaks the stack.
* `authenticate`: `gets(buf@rbp-0x90); strncmp(buf,"STRAYLIGHT_",11);` —
  **unbounded `gets()`**, but the frame is canary-protected (`mov %fs:0x28`).

## 3. Defeating the canary
The canary is per-process and identical in every frame. `log_request` runs
before `authenticate`, so we first leak it:
```
input "%15$p"  ->  "Logging: 0x<canary>"   (a random qword ending in 0x00)
```
Then in `authenticate` we overflow with the canary in its correct slot:
```
buf @ rbp-0x90  ->  canary @ rbp-0x8  =>  offset 136
[ 'A'*136 ][ canary ][ 'A'*8 (saved rbp) ][ ret2libc chain ]
```
`strncmp` failing (`Access denied`) is irrelevant — the overwritten return
address still runs once the canary check passes.

## 4. Chain
`setreuid(1023,1023)` (flag06) + `system("/bin/sh")` (movaps-aligned with a
`ret`), then the command is fed on stdin.

## 5. Interaction
We must read the leaked canary before building the second payload, so the
exploit talks to the process (subprocess) in one run: leak → parse canary →
send overflow → drive the shell (with a stdio-dodging delay).

## 6. Run
```
python3 exploit.py
-> c1t0kg9pklac7x4c7sn7iqgfppkz4usq
```

**flag06 = `c1t0kg9pklac7x4c7sn7iqgfppkz4usq`** (SSH password for level07)
