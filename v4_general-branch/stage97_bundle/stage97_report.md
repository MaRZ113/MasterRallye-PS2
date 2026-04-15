# Stage 97 report

## Focus
**Owner layout tuple packed-ref / scalar decode pass** for the QuickRace selector/button family.

## Main result
Stage 97 did not fully bit-decode every owner-side byte, but it **did** tighten the owner-side `A4` family into a usable local decoder split:

1. **compact owner state triplet**
   - `Up owner`: `a4 09 02`

2. **extended owner layout tuple**
   - `Right owner`: `a4 07 2d c4 10 01`

This is the first pass where the `A4` family can be treated as a coherent **owner-local state/layout record family**, not just leftover bytes.

## Strongest promotions

### A4 family marker
Both owner-side tails begin with `0xA4`, while companion tails remain in the `0x3E` family.
That strongly supports:
- `0xA4` = owner-local state/layout family
- `0x3E` = companion backlink / shared-root control family

### Compact owner state triplet
`AI_0_1 Up` stays the cleanest compact form:

- slot tag: `0x32`
- ordinal: `0x00EC`
- slot class: `0x3F`
- tail: `a4 09 02`

Best current read:
- `0xA4` = owner-family marker
- `0x09` = local state/layout selector
- `0x02` = branch/mode byte

### Extended owner layout tuple
`AI_0_1 Right` is the richer form:

- slot tag: `0x37`
- ordinal: `0x00F8`
- slot class: `0x30`
- tail: `a4 07 2d c4 10 01`

Best current read:
- `0xA4` = owner-family marker
- `0x07` = local state/layout selector
- `0x2DC4` = packed local ref / layout bucket candidate
- `0x10` = scalar/policy candidate
- `0x01` = branch/mode byte

Compared with the companion backlink `3e f8 00 01`, this clearly behaves like **owner-side metadata**, not a target ID.

## Practical interpretation
The local selector family now looks like:

- **owner slot record**
  - header (`slot_tag`, `ordinal`, `slot_class`)
  - `A4` family tail carrying state/layout metadata

- **companion slot record**
  - header
  - `3E` family backlink mini-record to owner ordinal

- **shared down**
  - `3E` family shared-root control

- **shared left**
  - extended back/escape ref (`1aec0104`)

## Honest limit
We still do **not** know the exact meaning of:
- owner selector bytes `0x09` and `0x07`
- packed value `0x2DC4`
- scalar `0x10`

But after Stage 97 the question is very narrow:
**what exact UI/layout semantics do `0x2DC4` and `0x10` encode inside the owner-side A4 tuple?**