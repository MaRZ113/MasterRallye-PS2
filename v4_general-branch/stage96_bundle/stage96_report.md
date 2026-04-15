# Stage 96 report

## Focus
**Owner-tail state/layout decoder pass** for the `QuickRace` selector/button family.

## Main result
Stage 96 did not bit-decode every owner-side byte, but it **did** separate owner tails into two useful local classes:

1. **compact owner state triplet**
   - `Up owner`: `a4 09 02`
2. **extended owner layout tuple**
   - `Right owner`: `a4 07 2d c4 10 01`

This is the first pass where owner-side tails can be discussed as **state/layout payloads** rather than miscellaneous leftovers.

## Strongest promotions

### Up owner
`AI_0_1 up` stays in the standard slot family:

- slot tag: `0x32`
- ordinal: `0x00EC`
- slot class: `0x3F`
- owner tail: `a4 09 02`

Best current interpretation:
- `0xA4` = owner-state family marker
- `0x09` = small local state id
- `0x02` = mode byte

This tail is short, owner-only, and structurally unlike the companion backlink `3e ec 00 02`.
That makes it a good candidate for a compact **enabled/active state triplet**.

### Right owner
`AI_0_1 right` now looks like a richer owner-side record:

- slot tag: `0x37`
- ordinal: `0x00F8`
- slot class: `0x30`
- owner tail: `a4 07 2d c4 10 01`

Best current interpretation:
- `0xA4` = owner-layout/state family marker
- `0x07` = local state/layout id
- `0x2DC4` = packed ref-like value
- `0x10` = stable scalar
- `0x01` = mode byte

Compared with the companion backlink `3e f8 00 01`, this looks far more like a **layout/state tuple** than a target reference.

### Down and Left
`Down` and `Left` remain in their own already-known lanes:

- `Down owner`: `3e e3 02`
- `Down companion`: `3e f7 00`
  - shared-root / list-root control family

- `Left`: `1aec0104`
  - extended back/escape reference family

## Practical interpretation
The local selector family now looks like:

- **owner slot record**
  - header (`slot_tag`, `ordinal`, `slot_class`)
  - owner-only state/layout tail

- **companion slot record**
  - header
  - backlink-like mini record to owner ordinal

- **shared down**
  - header
  - list-root control triplet

- **shared left**
  - extended back/escape ref

## Honest limit
We still do **not** know the exact meaning of:
- owner `state_id` bytes (`0x09`, `0x07`)
- the packed `0x2DC4` value
- whether scalar `0x10` is draw-priority-like, offset-like, or another tiny layout code

But after Stage 96 the question is now very narrow:
**what exact state/layout semantics do the owner-side `a4...` tails encode?**