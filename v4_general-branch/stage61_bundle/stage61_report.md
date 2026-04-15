# Stage 61 — page1 subgroup decoder pass

## Goal
Refine the Stage 60 `page1_low16_bankroot` model into a parser-grade late-FMV subgroup decoder using `CHALL04` as the seed, then test transfer to `TROPHY` and `BFGOOD1`.

## Inputs
- `/mnt/data/TNG.PAK`
- Stage 58 marker-span catalog
- Stage 60 late-FMV submodel outputs

## Main findings

1. **The page1 low16 target behaves like a subgroup anchor, not a final file offset.**
   For all three `page1_low16_bankroot` FMV entries, `page_lift_target = 0x10000 + low16(cand_u32_b)` lands inside a page1 node/subgroup region rather than directly on a final payload descriptor.

2. **`CHALL04` is the clean seed.**
   Its page1 target `0x15ef8` lands in the span beginning at `0x15ed0`, and the next local FMV path is `FMV\CHALL04.PSS` itself at `0x15fcb`. This is the first parser-grade local resolution for the page1 subgroup.

3. **`TROPHY` proves the anchor is shared.**
   Its page1 target `0x15fb6` lands in the `CHALL04` subgroup span instead of near the `TROPHY` string at `0x1b34f`, which means the page1 low16 does not identify the final member by itself. It identifies a shared subgroup root.

4. **`BFGOOD1` shows a binary-only variant of the same pattern.**
   Its page1 target `0x15d29` lands in a binary subgroup span (`0x15cdc..0x15d5c`) without a direct readable FMV name, implying the second step must use a local selector rather than plain nearest-string resolution.

5. **`trail_u16_a` is the best candidate for the member selector.**
   It is specific per record (`0x127c`, `0x0c4c`, `0x337c`) and echoes in a small number of other spans, including the owner FMV record itself. This fits a subgroup-member key much better than a size or raw TNG offset.

6. **`trail_u16_b` looks like a subgroup class/state word.**
   It clusters at `0x0900` (CHALL04/BFGOOD1) and `0x0600` (TROPHY), which is more consistent with subtype/class control than with payload size.

## Practical result
Stage 61 upgrades the late-FMV model from:

`page1 bankroot hint`

to:

`page1 subgroup anchor + local member selector`

This is not yet an exact `PAK -> TNG` bridge, but it is the first parser-grade decoder model for the `page1_low16_bankroot` subgroup.

## Recommended next step
**Stage 62 = selector-transfer decoder pass**

- bootstrap from `CHALL04` local forward resolution
- transfer the subgroup decoder to `TROPHY` and `BFGOOD1`
- score `trail_u16_a` echo locations as possible child/member nodes
- test whether `trail_u16_b` splits subgroup subtype (`0x0900` vs `0x0600`)
