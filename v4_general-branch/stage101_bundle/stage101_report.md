# Stage 101 report

## Focus
Broader **A4 subrecord family clustering** across canonical owner, companion, and variant carriers.

## Main result
`A4` now looks like a **broader owner-family binary subrecord marker**, not just a nav-tail marker.

## Cluster summary
- **owner_nav_tail**
  - `AI_0_1 @ 0x123` → compact owner-state triplet (`a4 09 02`)
  - `AI_0_1 @ 0x12f` → extended owner-layout tuple (`a4 07 2d c4 10 01`)
- **owner_render_value**
  - `AI_0_1 @ 0x2ff` → render/value curve bundle
  - `AI_0_1 @ 0x44d` → value/trailer bundle
  - `AI_0_1 @ 0x642` → 2d/render bridge bundle
- **companion_embedded**
  - `AI_0_2 @ 0x318` → embedded value/id subrecord, not nav-tail ownership
- **variant_owner_render**
  - `AI_3_3 @ 0x305` → variant render/value hoist
  - `AI_0_4 @ 0x226` → variant trailer/version subrecord

## Strongest takeaways
1. `AI_0_1` remains the **canonical owner-family reference carrier**.
2. `AI_0_2` stays a **companion** with `3E` backlink semantics; its single `A4` is incidental/embedded.
3. `AI_3_3` and `AI_0_4` confirm that `A4` semantics **transfer into variant owner-family carriers**, but outside the canonical nav-tail zone.
4. The next richest undecoded layer is the **owner_render_value** family inside `AI_0_1`.

## Practical consequence
We should stop treating `A4` as a single tail and instead decode it as a **family of local subrecord types**:
- nav-tail
- render/value
- variant trailer/hoist
