# Stage 65 — swapped-submodel local decoder split

## Goal
Split the `swapped_bankhint_hiword_root` late-FMV subgroup into local decoder branches instead of treating it as one blurry late model.

## Input basis
- Stage 64 transfer outputs for `BFGOOD2`, `CHALL06`, `BAGOO3`
- canonical `/mnt/data/TNG.000`
- local `TNG.PAK`

## Result summary
Stage 65 **did not produce one universal decoder**, but it did separate the subgroup into three practical branches.

### BFGOOD2 branch
Best candidate remains:
- `post_u32_m4.swap16`
- target window snapped to `0x3C280A47`
- valid `mpeg2video`, `512x256`
- visually coherent branded preview
- promoted as `soft_clean_local_decoder`

This is now the **anchor branch** of the subgroup.

### CHALL06 branch
Best candidate remains:
- `pre_u32_m28 - 0x50000000`
- target window snapped to `0x3C2C4A47`
- valid `mpeg2video`, `512x256`
- visually coherent preview
- but semantics still look closer to branded / track-menu FMV than to a true challenge member

This now looks like a **sibling/alias branch** rather than simple noise.

### BAGOO3 branch
Best candidate remains:
- `cand_u32_a - 0x40000000`
- target window snapped to `0x204DF85F`
- video-valid MPEG
- but contact sheet remains mostly black / degraded

This branch is still only **evidence-level** and should not be promoted yet.

## Main conclusion
The `swapped_bankhint_hiword_root` subgroup should be handled as a **local decoder family** with at least:
1. BFGOOD2-style branded preview branch
2. CHALL06-style sibling/alias branded branch
3. BAGOO3 degraded/evidence branch

So the subgroup is no longer one unresolved blob. It is now a **split late-FMV family**, with one strong branch, one plausible sibling branch, and one still-degraded branch.
