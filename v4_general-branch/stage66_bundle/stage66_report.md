# Stage 66 — BFGOOD2 exact-edge stabilization + CHALL06 alias verification

## Goal
1. Try to tighten `FMV\BFGOOD2.PSS` from a "nearest-pack" local decoder into a more exact payload edge.
2. Verify whether `FMV\CHALL06.PSS` is really a sibling/alias of the same branded late-FMV family rather than a distinct challenge-specific payload.

## Inputs
- Stage 64/65 local decoder outputs
- canonical `/mnt/data/TNG.000`
- local `TNG.PAK`
- Stage 65 contact sheets and extracted PSS windows

## Result summary
Stage 66 produced a **stronger operational stabilization** for `BFGOOD2` and a **much stronger verification** that `CHALL06` belongs to the same branded/sibling branch.

### BFGOOD2
The best route is still:
- `post_u32_m4.swap16`
- target `0x3C280C0A`
- nearest valid pack `0x3C280A47`
- snap delta `451` bytes

A wider local search around the record (±80 bytes, direct and swap16, with common high-nibble normalizations) did **not** reveal a better exact local field. The next best local direct-like value is far worse (`21983` bytes away).

So BFGOOD2 should now be treated as **stabilized soft-clean local decoder**, even though the field is not yet exact-zero.

### CHALL06
The best route remains:
- `pre_u32_m28 - 0x50000000`
- target `0x3C2C475C`
- nearest valid pack `0x3C2C4A47`
- snap delta `747` bytes

Visual comparison against `BFGOOD2` is strong:
- grayscale correlation is high
- perceptual hash distances are low relative to the BAGOO3 comparison
- both clips are `mpeg2video`, `512x256`, with close durations (`25.479s` vs `25.079s`)
- pack starts differ by only `0x44000`

This is now good enough to call `CHALL06` a **verified sibling/alias branch** of the same branded preview family.

### BAGOO3
No promotion. The best candidate remains video-valid but visually degraded/mostly black. It stays evidence-only.

## Main conclusion
Stage 66 did **not** find an exact-zero payload-edge for BFGOOD2, but it did accomplish the practical goal:
- BFGOOD2 is stabilized as the operational decoder for this local branch
- CHALL06 is now much more confidently a sibling/alias branded branch
- BAGOO3 remains the only weak late member in this subgroup

This means the subgroup is no longer structurally ambiguous. What remains is mostly quality cleanup, not major addressing uncertainty.
