# Stage 99 report — AI_3_3 raw owner-tail recovery / variant transfer

## Goal
Test whether the owner-side `A4` family recovered from canonical selector owner `AI_0_1` transfers to the variant carrier `AI_3_3`, or whether the variant uses a relocated/obscured representation.

## What was checked
- Cross-carrier field alignment between `AI_0_1.bin` and `AI_3_3.bin`
- Existing owner/companion split from Stage 97–98
- Variant-only fields that could displace or absorb owner-tail semantics

## Main result
No raw `A4` tuple was directly recovered for `AI_3_3`, but the carrier shows a **strong indirect transfer** of owner-side layout semantics:

- `Font ID`, `Offset`, `HJustification`, `Draw Priority` all transfer cleanly
- `AI_3_3` inserts `ViewC`, `GetSaveSize`, explicit `en3d ZBuffered`, `background_path`, and 2D render tokens
- This strongly supports a **render-specialized owner variant** rather than a companion-style carrier

## Practical conclusion
Stage 99 does **not** confirm a verbatim `A4` raw tail inside `AI_3_3`.
It **does** confirm that `AI_3_3` is best treated as a variant owner-family carrier whose owner semantics are likely shifted, fragmented, or partially hoisted into explicit render/value blocks.

## Best next move
Stage 100 should target deeper raw carrier recovery for `AI_3_3`, not because the model is weak, but because the remaining uncertainty is now very local.
