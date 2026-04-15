# Stage 88 report

## Goal
Control-word / nav-link decoder pass for the `selector_button_member_v2` family in QuickRace.

## Summary
Stage 88 does not claim a bit-perfect binary parser yet, but it does push the QuickRace AI/UI family from "field zones exist" to a more explicit **navigation/state decoder scaffold**.

The strongest result is that `AI_0_1.bin` now behaves like a primary `nav_link_table_v1` carrier:
- selector core (`Null`, `Index`, `Font ID`, `Offset`, `HJustification`)
- frontend logic class (`gaFrontendStandardButtonAI`)
- four-direction nav quartet (`Up Path`, `Right Path`, `Down Path`, `Left Path`)
- explicit enabled state (`Enabled`, `True`)
- render/ui tail (`Draw Priority`, `en3d Model`, `ZBuffer`, `2d Image Bank`, `Colour`)
- embedded `Draw Priority = 38`

`AI_0_2.bin` is now best interpreted as a **path/text companion** that reuses the same nav tail but adds text/layout fields and a `Pulse` state.

`AI_3_3.bin` remains a real sibling/variant, but it is no longer treated as the primary nav carrier. Its render/view fields make it a variant-specific decoder candidate rather than the canonical member.

## Key findings

### 1. The nav quartet is structurally real
For `AI_0_1.bin`, the four directional path tokens occur contiguously and are immediately followed by `Enabled` and `True`.
This is now strong evidence for a local navigation table rather than random token co-occurrence.

### 2. Shared button logic spans carriers
Both `AI_0_1.bin` and `AI_0_2.bin` include `gaFrontendStandardButtonAI`.
That suggests the button logic is broader than the primary selector carrier and can extend into the path/text companion.

### 3. Control-word semantics are still the main missing piece
The gaps between adjacent selector and nav fields are too regular to dismiss as noise.
Stage 88 interprets them as compact control slots / transition words, but not yet as fully decoded integers or link indices.

## Practical conclusion
QuickRace now has a stronger non-video decoder scaffold:

- `selector_button_member_v2` -> primary nav/state carrier
- `path_text_member_v2` -> text/path companion with reused nav tail
- `selector_button_member_v2_variant` -> render/view specialized sibling

That is enough to justify a next pass aimed specifically at **binary control-word semantics and exact link-target ownership**.