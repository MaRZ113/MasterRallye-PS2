# Stage 87 report

## Goal
Field decoder pass for `selector_button_member_v2` and companion QuickRace AI/UI carriers.

## Summary
Stage 87 moves QuickRace AI/UI analysis from class recognition to **field-level scaffolding**. The strongest result is that `AI_0_1.bin` now exposes a stable field layout with selector, navigation, UI-property, and render-tail zones. `AI_0_2.bin` and `AI_3_3.bin` confirm this is a reusable family rather than a one-off carve.

## Key findings

### 1. `AI_0_1.bin` is the primary selector/button field carrier
Stable order:
- AI header
- selector/type/runtime-class core
- selector null/key/list tokens
- UI props (`Font ID`, `Offset`, `HJustification`)
- nav cluster (`Up/Right/Down/Left Path`, `Enabled`)
- render/ui tail (`Draw Priority`, `en3d Model`, `ZBuffer`, `2d Image Bank`, `Colour`)
- embedded explicit `<Value Name="Draw Priority" Type="Int" Value="38"/>`

### 2. `AI_0_2.bin` is a path-backed text companion, not noise
It carries:
- runtime class `enUIFormattedTextAI`
- `Frontend/QuickRace/Current...` path reference
- text/layout props (`Font ID`, `Offset`, `Horizontal Justification`, `Max. Width`, `Height`, `Colour`)
- shared nav/button tail (`gaFrontendStandardButtonAI`, `Up/Right/Down/Left`, `Enabled`, `Pulse`)

### 3. `AI_3_3.bin` is a true variant of the same family
It preserves selector/list hints but mixes in variant-specific view/render data:
- `ViewC`
- `Draw Priority`
- `Image Bank Index`
- `2dGlobal`
- embedded `en3d ZBuffered = True`
- background path `frontend\backgrounds\bg_newnetwork`

## Practical conclusion
QuickRace now has a field-level non-video decoder scaffold:
- `selector_button_member_v2`
- `path_text_member_v2`
- `selector_button_member_v2_variant`

This is enough to move from "structured carrier found" to "carrier fields can be decoded and mapped by offset/zones".
