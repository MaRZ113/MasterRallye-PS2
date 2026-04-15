# Stage 90 report

Stage 90 focused on decoding the compact target IDs that sit immediately after
`Up Path / Right Path / Down Path / Left Path` in the QuickRace selector/button
family (`AI_0_1`, `AI_0_2`, `AI_3_3`).

## Main result

This pass closes the main uncertainty left from Stage 89:

- `AI_0_1.bin` is the **canonical selector owner**
- `AI_0_2.bin` is the **path/text companion**
- `AI_3_3.bin` is a **render/view variant**
- `Up/Right/Down/Left` use **compact scene-local target refs**, not plain string refs

## Best compact slot findings

For the primary owner (`AI_0_1.bin`):

- `Up Path`   -> compact id `0x00EC`
- `Right Path`-> compact id `0x00F8`
- `Down Path` -> compact id `0x00F5`
- `Left Path` -> stable extended block `1aec0104` (likely wider than plain u16)

For the companion (`AI_0_2.bin`):

- `Up Path`   -> compact id `0x00ED`
- `Right Path`-> compact id `0x00F9`
- `Down Path` -> compact id `0x00F5`
- `Left Path` -> same stable extended block `1aec0104`

This is especially useful because the owner/companion relationship now has a
numerical signature:

- `Up`: `0x00EC` vs `0x00ED`
- `Right`: `0x00F8` vs `0x00F9`
- `Down`: shared `0x00F5`
- `Left`: shared extended slot block

That strongly suggests paired selector/text nodes rather than unrelated reuse.

## Honest limit

The exact mapping from compact target ids (`0x00EC`, `0x00F8`, `0x00F5`, ...)
to concrete QuickRace member indices is not finished yet. The left slot also
still looks like an extended encoding rather than the simple u16 form used by
the other directions.

## Practical meaning

Stage 90 turns the nav table from a vague "binary control zone" into an
explicit, local, scene-aware compact target layer. That is already enough to
treat the QuickRace selector/button carrier as a real parser target rather than
a loose structured blob.
