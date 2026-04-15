# Stage 86 report

## Goal
QuickRace AI/UI block local decoder pass using runtime-class names confirmed by `SLES_509.06`.

## Summary
Stage 86 confirms that the strongest QuickRace carrier is not a `<Value>` member but an **AI/UI button carrier**. The best new local decoder class is `selector_button_member_v2`, anchored by `AI_0_1.bin`.

## Key findings

### 1. Runtime-class alignment from ELF is real
The extracted QuickRace members line up with runtime strings found in `SLES_509.06`:
- `enUITextButtonAI`
- `enUIFormattedTextAI`
- `gaFrontendStandardButtonAI`
- `Frontend/QuickRace/...`
- `Font ID#`
- `Draw Priority`
- `Up Path`, `Right Path`, `Down Path`, `Left Path`
- `en2d Image Bank Index`, `Draw 2D`, `2dGlobal`

This means our non-video extraction is no longer just semantic guesswork; it is being anchored to real runtime class names.

### 2. `AI_0_1.bin` is now the primary QuickRace selector decoder
It coherently exposes:
- selector/list semantics: `Index`, `Null`, `List`
- button carrier: `enUITextButtonAI`
- frontend logic class: `gaFrontendStandardButtonAI`
- navigation fields: `Up/Right/Down/Left Path`
- UI properties: `Font ID`, `Offset`, `Horizontal Justification`, `Draw Priority`

This is the strongest current candidate for a reusable QuickRace local decoder class.

### 3. `AI_0_2.bin` is a path-backed text companion
It exposes:
- `Frontend/QuickRace/Current...`
- `enUIFormattedTextAI`
- `gaFrontendStandardButtonAI`
- text/UI properties like `Font ID`, `Offset`, `Horizontal Justification`, `Max. Width`, `Height`, `Colour`

So the selector/list logic seems to split across a button carrier and a text/path companion.

### 4. `AI_3_3.bin` is a variant, not noise
It still behaves like the same broad family, but with extra render/view terms like `ViewC`, `Image Bank Index`, `2dGlobal`.

## Practical conclusion
QuickRace now has its own real local decoder class family:
- `selector_button_member_v2`
- `path_text_member_v2`
- `selector_button_member_v2_variant`
- plus the smaller `list_transition_member_v1`

This is enough to move from generic scene carving toward a true AI/UI member decoder pass.
