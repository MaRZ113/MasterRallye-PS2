# Stage 89 report

## Focus
Exact nav-link target / control-word semantics pass for the QuickRace AI/UI family.

## Inputs
- Stage 86 structured decoder classes
- Stage 87 field-zone map
- Stage 88 nav-link/control-word windows
- Raw extracted carriers:
  - AI_0_1.bin
  - AI_0_2.bin
  - AI_3_3.bin

## Core result
Stage 89 did **not** fully decode the binary nav target IDs, but it **did** resolve the ownership question and upgraded the model from:

`field zones + nav quartet`

to:

`primary selector owner + shared compact nav slot table + companion text carrier`

### Stable decisions
- `AI_0_1.bin` is the **canonical selector owner**.
- `AI_0_2.bin` is the **path/text companion** with shared nav tail.
- `AI_3_3.bin` is a **render/view specialized sibling**, not the canonical nav owner.
- The `Up/Right/Down/Left Path` slots behave like **compact scene-local refs / indices**, not plain string references.

## Why this matters
This is the first clean point where the non-video decoder starts to look like a small local parser:
- selector ownership
- companion ownership
- compact nav/state slot table
- render/view sibling separation

## What remains
The missing edge is now very focused:
decode the compact IDs/control words that sit between the nav labels and the next slot.

That makes Stage 90 a very direct next move.
