# Stage 95 report

## Focus
**Standard slot `control_a/control_b` semantics pass** for the `QuickRace` owner/companion selector family.

## Main result
Stage 95 did not produce a bit-perfect decode of every trailing control byte, but it **did** firm up the standard slot record into a much more explicit local model:

`[slot_tag][ordinal_le_u16][slot_class][tail...]`

Where:

- `slot_tag`
  - `0x32` = primary owner/companion pair family
  - `0x37` = secondary pair and shared-list family
  - `0x1a` = extended left/back ref family

- `ordinal_le_u16`
  - stable local ordinals:
    - `0x00ec`
    - `0x00ed`
    - `0x00f5`
    - `0x00f8`
    - `0x00f9`

- `slot_class`
  - `0x3f` = owner primary
  - `0x34` = companion primary **or** owner-down shared root
  - `0x30` = secondary pair
  - `0x36` = companion-down shared root

## Strongest semantic promotions

### Companion tails
For companion `up` and `right`, the tail is now strongly interpreted as a **backref-like mini record**:

- `AI_0_2 up` tail: `3e ec 00 02`
  - points back to owner ordinal `0x00ec`
  - mode byte `0x02`

- `AI_0_2 right` tail: `3e f8 00 01`
  - points back to owner ordinal `0x00f8`
  - mode byte `0x01`

This is the clearest evidence so far that companion slots carry **explicit linkage back to the owner-side selector nodes**.

### Owner tails
Owner `up` / `right` carry different tails:

- `AI_0_1 up` tail: `a4 09 02`
- `AI_0_1 right` tail: `a4 07 2d c4 10 01`

These no longer look like target ordinals. They behave more like **owner-side state/layout metadata** or local mode payloads.

### Shared down-root
`Down` remains shared (`0x00f5` on both owner and companion), but the tails:

- owner: `3e e3 02`
- companion: `3e f7 00`

look more like **shared-root / list-fabric control triplets** than the owner/companion backref forms used by `up` and `right`.

### Left path
`Left` remains fully separate:

- shared payload: `0x1aec0104`
- identical on owner and companion

This is still best treated as an **extended back/escape ref**, not a compact ordinal slot.

## Practical interpretation
The local selector family now looks like:

- owner slots:
  - own compact ordinal
  - own slot-class
  - owner-specific state/layout tail

- companion slots:
  - own compact ordinal
  - own slot-class
  - backlink-like tail to owner ordinal plus tiny mode byte

- shared `down`:
  - shared ordinal to list-root
  - shared-root control triplet

- shared `left`:
  - extended back/escape ref

## Honest limit
The exact semantics of:
- owner `a4...` tails
- shared `down` triplets
- extended left payload structure

are still not fully decoded.

But after Stage 95, the problem is no longer “what is this record at all?” — it is specifically:
**what do the owner-side state bytes and shared-root control triplets encode?**
