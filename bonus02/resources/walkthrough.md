# bonus02 — walkthrough

**Binary:** `/home/bonus02/flatline` (SUID `flagbonus02`) — **no source**
**Goal:** read `/home/flagbonus02/.pass`

## Recon
```
PIE (ASLR off), NX, canary. main setreuid()s, so /bin/sh keeps the euid.
main: new_construct(DIXIE); new_construct(WINTERMUTE);
      delete_construct(0); update_construct(0); run_construct(0);
```

## Bug — use-after-free
A construct is `malloc(0x70)` with a `data` area at `+0x28` and a
callback at `+0x68`. The sequence is a textbook UAF:
* `delete_construct(0)` → `free(constructs[0])` but **does not null the pointer**.
* `update_construct(0)` → `read(constructs[0] + 0x28, 0xa0)` into the **freed** chunk.
* `run_construct(0)` → `constructs[0]->callback(constructs[0] + 0x28)`.

## Exploit
The `update` write lets us set the freed construct's fields:
```
data offset 0  -> construct+0x28  (rdi passed to the callback)
data offset 64 -> construct+0x68  (the callback)   (0x68 - 0x28 = 0x40 = 64)
```
So `data[0..7] = "/bin/sh"`, `data[64] = system` → `run_construct(0)` calls
`system("/bin/sh")` as flagbonus02.

## Run
```
python3 exploit.py   ->   l2asy8pwncmqtbwfsu12w1hfv3yf6c30
```

**flagbonus02 = `l2asy8pwncmqtbwfsu12w1hfv3yf6c30`** (SSH password for bonus03)
