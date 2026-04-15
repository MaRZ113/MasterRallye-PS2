# Stage 94 report

## Summary
Stage 94 targeted the owner/companion local ordinal fabric inside the QuickRace selector/text pair.

The strongest result is a stable **standard slot record** for `Up`, `Right`, and `Down`:

- shape: `[slot_tag][u16 ordinal][control_a][control_b]`
- owner/carrier: `AI_0_1.bin`
- companion/carrier: `AI_0_2.bin`

The `Left Path` slot is now clearly separated as an **extended non-u16 record** with shared payload `0x1AEC0104` in both owner and companion.

## Promoted findings

### 1. Standard ordinal fabric
For the standard slots, the bytes immediately after the label resolve cleanly into:
- `slot_tag` (`0x32` for Up, `0x37` for Right/Down)
- `u16 ordinal` (`0x00EC`, `0x00ED`, `0x00F5`, `0x00F8`, `0x00F9`)
- two stable carrier-local control words (`control_a`, `control_b`)

### 2. Owner/companion pairing is now structural
The owner/companion pair is no longer just a semantic guess:
- `Up`: `0x00EC` vs `0x00ED`
- `Right`: `0x00F8` vs `0x00F9`
- `Down`: shared `0x00F5`
- `Left`: shared `0x1AEC0104`

This gives a strong local pairing model:
- owner = primary selector carrier
- companion = paired text/path carrier
- Down = shared list-root hop
- Left = shared back/escape action

### 3. Down is the best root-linked slot
`0x00F5` remains the strongest anchor because Stage 93 already tied it to the scene-root/list-root prelude.
Stage 94 shows that the local owner/companion slots still wrap that same shared ordinal with per-carrier control words.

## What is still open
- exact bit/field semantics of `control_a` and `control_b`
- whether `slot_tag` is directional-only or also encodes record class
- exact meaning of `0x1AEC0104` beyond shared back/escape behaviour

## Outcome
Stage 94 moves the model from “compact IDs exist” to a more concrete local decoder:

**owner/companion carrier → standard slot record → ordinal + local controls**

That is enough to justify a dedicated follow-up on the control words themselves.
