# Stage 63 — post-member edge decoder pass

## Goal
Finish the missing edge for the late-FMV `page1_low16_bankroot` subgroup by moving from the exact named member records recovered in Stage 62 to exact `TNG.000` media windows.

## Inputs
- `/mnt/data/TNG.PAK`
- canonical `/mnt/data/TNG.000`
- Stage 62 exact member decoder for `CHALL04 / TROPHY / BFGOOD1`

## Main result
Stage 63 closes the remaining gap for the `page1_low16_bankroot` late-FMV subgroup.

The working decoder is now:
1. `page_index + low16(cand_u32_b)` -> shared page1 subgroup anchor
2. `(trail_u16_b << 16) | trail_u16_a` -> exact named late-FMV member record in `TNG.PAK`
3. `pre_u32_m24` (the u32 at `string_offset - 24`) -> **direct exact TNG pack start**

This is the first honest exact named late-FMV `PAK -> TNG` bridge for the project.

## Exact bridges recovered
### `FMV\CHALL04.PSS`
- exact member key: `0x0900127c`
- direct post-member edge field: `pre_u32_m24 = 0x32E14A2F`
- extracted window start: `0x32E14A2F` (exact pack hit, delta 0)
- extracted window length: `0x5C0004`
- ffprobe: `mpeg2video`, `512x256`, duration `25.000 s`
- contact sheet: clear multi-vehicle challenge FMV with BFGoodrich branding

### `\FMV\TROPHY.PSS`
- exact member key: `0x06000c4c`
- direct post-member edge field: `pre_u32_m24 = 0x3D9EFE11`
- extracted window start: `0x3D9EFE11` (exact pack hit, delta 0)
- extracted window length: `0x220004`
- ffprobe: `mpeg2video`, `512x256`, duration `24.960 s`
- contact sheet: trophy / checkered-globe award FMV

### `FMV\BFGOOD1.PSS`
- exact member key: `0x0900337c`
- direct post-member edge field: `pre_u32_m24 = 0x31164E1A`
- extracted window start: `0x31164E1A` (exact pack hit, delta 0)
- extracted window length: `0x480004`
- ffprobe: `mpeg2video`, `512x256`, duration `25.000 s`
- contact sheet: BFGoodrich-branded preview FMV

## Why this is stronger than the earlier candidates
Stage 57 and Stage 60 already showed weaker / alternate candidates from `cand_u32_a` with high-bit normalization.
Those windows are still valid media, but they require normalization and pack snapping and remain less exact than the new Stage 63 decoder.

In contrast, the new `pre_u32_m24` field:
- lands directly on the pack start for all three tested members
- gives semantically plausible named FMVs
- works only after the Stage 62 exact member resolution step

That means it behaves like a real **post-member payload edge**, not just another nearby media hint.

## Practical interpretation
For the `page1_low16_bankroot` late-FMV subgroup, the project now has a complete parser-grade bridge:

`PAK subgroup anchor -> exact named member -> exact TNG pack window`

This does **not** yet mean every late FMV uses the same final edge field, but it proves the architecture and supplies the first exact named late-FMV bridge.

## Recommended next step
**Stage 64 = late-submodel transfer pass**

Apply the same post-member edge test to the next subgroup (`swapped_bankhint_hiword_root`: `BAGOO3 / CHALL06 / BFGOOD2`) and see whether it has:
- the same `pre_u32_m24` edge,
- or a sibling post-member payload field.
