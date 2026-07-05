# Rainfall

Solutions and write-ups for the **Rainfall** project — an introduction to the
exploitation of ELF (i386, 32-bit) binaries.

Each user `levelX` owns a setuid binary. Exploiting it yields a shell as the
next user, whose `~/.pass` is the password (the "flag") used to `su`/`ssh` into
that next level. The chain is:

```
level0 -> level1 -> ... -> level9 -> bonus0 -> bonus1 -> bonus2 -> bonus3 -> end
```

## Layout

Every level directory follows the structure required by the subject:

| File / dir      | Contents                                                        |
| --------------- | --------------------------------------------------------------- |
| `flag`          | The recovered password of the **next** user.                    |
| `source`        | The exploited binary reconstructed as readable C/C++.           |
| `walkthrough`   | Step-by-step explanation of the vulnerability and the exploit.  |
| `Ressources/`   | Proof material: disassembly, payloads, exploit scripts, notes.  |

No compiled binary is ever committed (per the subject).

## Vulnerability map

| Level  | Bug class                     |
| ------ | ----------------------------- |
| level0 | logic gate (`atoi`)           |
| level1 | stack overflow (`gets`)       |
| level2 | overflow, sanitized saved-EIP |
| level3 | format string                 |
| level4 | format string                 |
| level5 | format string -> GOT overwrite|
| level6 | heap overflow (fn pointer)    |
| level7 | heap overflow -> GOT overwrite|
| level8 | logic bug (mini-shell)        |
| level9 | C++ vtable overwrite          |
| bonus0 | stack overflow (concat)       |
| bonus1 | signed integer / `memcpy`     |
| bonus2 | stack overflow (LANG greeting)|
| bonus3 | logic bug (`atoi` index)      |
