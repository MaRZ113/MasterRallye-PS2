# Stage 106 report

## Goal
Resolve whether `2dGlobal` and `AI_List` play the same role inside the strongest owner-side bridge (`AI_0_1 @ 0x642`), or whether one is a namespace/bank token and the other is the concrete list-root family behind Down target `0x00F5`.

## Main result
Stage 106 supports the following stacked model:

`2d File / 2d Image Bank Index` -> `A4 bridge` -> `2dGlobal` -> `AI_List` -> `0x00F5` -> `QuickRace_AI_List_AI_List_02`

This means:
- `2dGlobal` is **not** the concrete Down target.
- `AI_List` is the concrete scene-local list/container family.
- `0x00F5` remains the compact shared list-root target reached by both owner and companion Down Path slots.

## Strongest supports
- Stage 105 already tied `2dGlobal` and `AI_List` to the strongest owner bridge.
- Stage 93 promoted `0x00F5` from scene-root prelude evidence (`0000f5030000000b`) as a root/list anchor.
- Stage 91/92 mapped owner+companion Down Path to `0x00F5`.
- Runtime crosswalk from `SLES_509.06` keeps `en2d 2dGlobal` aligned with render/global scope and `AI_List` aligned with concrete list/container semantics.

## Practical conclusion
Stage 106 does not claim a bit-perfect decode of `2dGlobal`, but it *does* resolve the semantic layering:

- render asset context
- render/global namespace token
- list/container family
- compact list-root target

That is enough to treat `0x00F5` as a resolved list-root target family and move the next direct effort to the list container itself.
