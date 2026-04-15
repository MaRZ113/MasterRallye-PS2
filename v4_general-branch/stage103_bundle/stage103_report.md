# Stage 103 report

## Goal
Stage 103 focused on the strongest secondary `A4` subtype identified in Stage 102:
`AI_0_1 @ 0x642`, labelled **render_2dglobal_bridge**.
The pass tried to answer a narrower question than Stage 102:
what exactly is the field correlation around the canonical owner-side bridge,
and how does that compare to the variant carriers `AI_3_3` and `AI_0_4`?

## Main outcome
The cleanest result is that `AI_0_1 @ 0x642` really does behave like a
**bridge-center subrecord** between two semantically different local zones:

- a **pre-zone** carrying `2d File` / `2d Image Bank Index`
- a **post-zone** carrying `2dGlobal` / `AI_List`

The `A4` byte sits at local offset `0x40`, with the strongest token layout in the whole family:
- `2d File` at `-52`
- `2d Image Bank Index` at `-34`
- `2dGlobal` at `+19`
- `AI_List` at `+33`

That is now the clearest owner-side render/value handoff we have.

## Strongest semantic promotions
1. **AI_0_1 @ 0x642**
   - best read: `render_2dglobal_bridge`
   - role: owner-side handoff from 2d file/image-bank zone into `2dGlobal` + `AI_List`
   - confidence: high

2. **AI_0_1 @ 0x2FF**
   - best read: `render_curve_or_formatted_bridge`
   - role: owner-side bridge from render/image-bank state toward formatted/font styling
   - confidence: medium

3. **AI_3_3 @ 0x305**
   - best read: `variant_render_value_hoist`
   - role: variant owner-family hoist between `GetSaveSize` and `ZBuffered/background_path`
   - confidence: high

4. **AI_0_4 @ 0x226**
   - best read: `variant_trailer_version_bundle`
   - role: late trailer/version sidecar near `Colour` and `s_Version`
   - confidence: medium

## Honest limit
This pass did **not** produce a bit-perfect decode of the binary words inside `AI_0_1 @ 0x642`.
What it *did* do is make the local bridge layout much clearer and show that the variant carriers
inherit the family semantically, but not with the same byte-for-byte layout.

## Best next move
**Stage 104 = render_2dglobal_bridge byte-lane decode pass**
