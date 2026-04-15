# Stage 64 — late-submodel transfer pass

## Goal
Test whether the exact late-FMV payload-edge mechanism found in Stage 63 for the `page1_low16_bankroot` subgroup transfers to the next late-FMV subgroup: `swapped_bankhint_hiword_root` (`BAGOO3`, `CHALL06`, `BFGOOD2`).

## Input basis
- Canonical `/mnt/data/TNG.000` rebuilt and SHA256-verified earlier in the run.
- `TNG.PAK` local copy in `/mnt/data/TNG.PAK`.
- Stage 60 late-FMV neighborhoods and Stage 63 exact page1 bridge.

## Result summary
Stage 64 produced a **partial but honest transfer**.

### Strongest transfer
`FMV\BFGOOD2.PSS`
- best candidate: `post_u32_m4.swap16`
- normalized target: `0x3C280C0A`
- nearest pack: `0x3C280A47`
- snap delta: 451 bytes
- ffprobe: `mpeg2video`, `512x256`, `13.811 s`
- visual outcome: coherent branded preview with visible Master Rallye overlay
- status: `soft_clean_transfer`

### Medium / provisional transfer
`FMV\CHALL06.PSS`
- best candidate: `pre_u32_m28 - 0x50000000`
- normalized target: `0x3C2C475C`
- nearest pack: `0x3C2C4A47`
- snap delta: 747 bytes
- ffprobe: `mpeg2video`, `512x256`, `13.251 s`
- visual outcome: coherent branded preview, but semantics currently look closer to track/menu branded material than to a challenge FMV
- status: `soft_clean_transfer_semantic_mismatch`

### Weak / evidence only
`FMV\BAGOO3.PSS`
- best candidate: `cand_u32_a - 0x40000000`
- normalized target: `0x204E0004`
- nearest pack: `0x204DF85F`
- snap delta: 1957 bytes
- ffprobe: `mpeg2video`, `512x256`, `12.593 s`
- visual outcome: mostly black / degraded
- status: `evidence_transfer_only`

## Main conclusion
The Stage 63 exact decoder **does not transfer wholesale** into the next late subgroup.
Instead, `swapped_bankhint_hiword_root` behaves like a **heterogeneous local-decoder family**:
- BFGOOD2 has a strong candidate through `post_u32_m4.swap16`
- CHALL06 has a separate provisional route via `pre_u32_m28 - 0x50000000`
- BAGOO3 remains unresolved beyond degraded evidence

So Stage 64 did not produce a universal exact decoder, but it did prove that late-FMV transfer can continue beyond the Stage 63 subgroup — just with subgroup-local payload-edge rules rather than a single shared mechanism.