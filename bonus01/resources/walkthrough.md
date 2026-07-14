# bonus01 — walkthrough

**Binary:** `/home/bonus01/zion` (SUID `flagbonus01`, x86-64) — **no source**
**Goal:** read `/home/flagbonus01/.pass`

## Recon
```
PIE (ASLR off -> base 0x555555554000), NX, canary.
main: setreuid(geteuid(),geteuid()); ... alloc_block(ALPHA); alloc_block(BETA);
      list_blocks(); free_block(0); free_block(1);
```
The `setreuid` means `/bin/sh` keeps the flagbonus01 euid.

## Bug
Each block = `{int id; int size; char label[16]; void(*on_free)()}` (malloc 0x20)
plus a `data` buffer (malloc(size)). `alloc_block`:
```c
read(0, data, size + 0x40);   // 0x40-byte HEAP OVERFLOW
free(data);
```
`free_block(i)` runs `blocks[i]->on_free(blocks[i])`.

## Exploit — tcache-driven callback hijack
block0's data (0x40) is freed, so block1's `data` reuses it and block1's
metadata lands right after, so block1's `read(data, 0x80)` overflows into its
**own metadata**:
```
input offset 80  -> metadata[0]   (this pointer is passed as rdi)
input offset 104 -> metadata[0x18] (the on_free callback)
```
Put `metadata[0] = "/bin/sh"` and `callback = system`; then `free_block(1)` runs
`system("/bin/sh")` as flagbonus01 (euid preserved by main's setreuid).

## Run
```
python3 exploit.py   ->   8g8nnrrtsasgf9i7etv0s9a21j5f9riw
```

**flagbonus01 = `8g8nnrrtsasgf9i7etv0s9a21j5f9riw`** (SSH password for bonus02)
