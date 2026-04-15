# Stage 59 — auxiliary numeric table / root-link pass

## Goal
Follow the strongest Stage 58 lead: low-offset numeric/control regions in `TNG.PAK` are likely part of an auxiliary root-link layer that points into the main node fabric rooted at `0x1760`.

## Inputs
- `/mnt/data/TNG.PAK`
- Stage 58 marker-span and FMV-neighborhood catalogs
- canonical `/mnt/data/TNG.000` (verified, not directly carved in this step)

## What was done
1. Re-scanned the prelude (`0x0180–0x1760`) as packed little-endian `u16 target / u16 control` pairs.
2. Kept only pairs whose target lands inside the main node region (`>= 0x1760`).
3. Linked those targets to the nearest marker span and nearest clear path-bearing record.
4. Built root-link clusters by table locality and target locality.
5. Cross-checked the resulting target pairs against clear FMV entry neighborhoods.

## Concrete findings

### 1. The low-offset regions really do behave like root-link tables
Treating the prelude as packed `u16 target, u16 control` pairs yields a large population of valid pointers into the main node region.
The densest useful families line up with the same low-offset zones Stage 58 already highlighted (`0x0180`, `0x0328`, `0x0DEC`).

### 2. The root-link layer points into semantic subtrees, not random bytes
Representative clusters:
- `0x0DEC` points into the FMV neighborhood around `FMV\FUJ3.PSS` and nearby frontend strings.
- `0x0328` points into a mixed subtree containing `VEHICLES\MEGANE\COMPLETE.PSM`, `...PAVEMENT-TGA.GXI`, `TITLESCREEN` fragments, etc.
- `0x0180` points into a deeper course/Turkey subtree with `PACENOTES`, `ELF2`, `LOAD`, and a full `TURKEY_S2_FLIP` texture path.

This is strong evidence that the prelude is an auxiliary link fabric into the main trie/node layer.

### 3. Early FMV entries have direct or near-direct root-link hits
The bridge catalog shows that early FMV entries are not isolated strings:
- `FMV\FUJ3.PSS` has multiple prelude targets within 6–31 bytes of the string/prev-marker neighborhood.
- `FMV\GO2.PSS` has an exact hit to its previous marker (`0x6d00`) from prelude offset `0x16da`.
- `FMV\MICROIDS.PSS` has an exact hit to the string offset (`0x786c`) from prelude offset `0x0c94`.
- `FMV\CHALL02.PSS`, `FMV\INV1.PSS`, `FMV\ELF3.PSS` also have low-delta root-link hits.

That is the first hard evidence that the auxiliary numeric layer and the clear FMV records are part of the same addressing mechanism.

### 4. Later FMV entries overflow the simple u16 model
The later FMV strings (`MASTER03`, `CHALL04`, `BAGOO3`, `TROPHY`, `FUJ2`, `BFGOOD1`) sit beyond `0xFFFF` in the node region.
They do not receive the same neat direct u16 root-link hits.
This strongly suggests a second stage is involved for those records:
- banked/page-relative addressing,
- second-level node indirection,
- or a higher-order table that combines root-link targets with structural class/control words.

### 5. The `control` halfword is likely structural, not just decoration
The same target subtrees are reached under recurring control values such as `0x0000`, `0x6400`, `0x7800`, `0xA400`, `0xB800`, `0xE400`, `0xE800`, `0xF400`, `0xF800`.
These look much more like class/edge/control tokens than raw resource sizes.

## Practical interpretation
Stage 59 does not yet recover an exact universal `path -> absolute TNG offset/size` parser.
But it does establish a much sharper model:

- `0x1760` anchors the main node fabric.
- The prelude contains a real auxiliary root-link layer.
- That root-link layer can already reach early FMV nodes directly.
- Later FMV nodes almost certainly need one more indirection/banking step.

## Recommended next step
**Stage 60 = second-level bank/page decoding pass**

Focus:
1. isolate the late FMV subtree (`MASTER03`, `CHALL04`, `BAGOO3`, `TROPHY`, `FUJ2`, `BFGOOD1`)
2. correlate it with repeated control halfwords and nearby numeric words
3. test whether a bank/page model lifts late node offsets above `0xFFFF`
4. then try to recover the first exact `PAK entry -> TNG window` bridge for named FMV assets
