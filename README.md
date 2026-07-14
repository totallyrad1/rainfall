# Rainfall (v2 — "A binary exploitation project", version 5.0)

Exploitation of **x86-64 ELF** SUID binaries on Ubuntu 24.04, with modern
mitigations (NX, stack canaries, ASLR, RELRO, PIE) switched on level by level.

Each user `levelNN` owns a SUID binary owned by `flagNN`. Exploiting it to run
as `flagNN` lets us read `/home/flagNN/.pass`, which is the SSH password for
`levelNN+1`. Chain: `level00 → … → level10` (boss), then `bonus01 → bonus05`.

## Layout (per the subject)

Each level directory contains:

| File / dir     | Contents                                                       |
| -------------- | -------------------------------------------------------------- |
| `flag`         | the recovered flag (SSH password for the next level)           |
| `resources/`   | the pwntools `exploit.py`, a `walkthrough.md`, and the source  |

No binaries are committed. Exploits are written with **pwntools** (Python).
The v1 (32-bit) project is archived under [`rainfall-v1/`](./rainfall-v1).

## Running the exploits

A Python venv with pwntools lives in `.venv/` (git-ignored):

```
python3 -m venv .venv && . .venv/bin/activate && pip install pwntools
```

Each `exploit.py` builds a payload (`python3 exploit.py > payload`); the
`walkthrough.md` shows how it is delivered to the binary on the VM.

## Mitigation / technique map

| Level   | Key mitigation state              | Technique                              |
| ------- | --------------------------------- | -------------------------------------- |
| level00 | exec stack, no canary/PIE, ASLR off | shellcode on stack + NOP sled        |
| level01 | _tbd_                             | _tbd_                                  |
| …       |                                   |                                        |
| level10 | NX + canary + ASLR (boss)         | leak + canary defeat + ret2libc ROP    |
