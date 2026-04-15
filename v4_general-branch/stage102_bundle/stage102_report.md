# Stage 102 report

## Goal
Stage 102 focused on the **owner_render_value subrecord semantics** branch opened by Stage 101.
Instead of treating all `A4` occurrences as one thing, this pass compared the secondary `A4` records in
`AI_0_1` with the variant carriers `AI_3_3` and `AI_0_4`, plus the incidental companion occurrence in `AI_0_2`.

## Main outcome
The strongest practical result is that the `A4` family now splits into:
- canonical **owner_render_value** subrecords inside `AI_0_1`
- **variant_owner_render** hoists inside `AI_3_3` / `AI_0_4`
- a non-transferable **companion_embedded** fragment in `AI_0_2`

## Best semantic promotions
1. **AI_0_1 @ 0x642** stays the best anchor:
   - tokens: `2d File`, `2d Image Bank Index`, `2dGlobal`, `AI_List`
   - best read: **render_2dglobal_bridge**
   - this now looks like the cleanest bridge from owner render state into a `2dGlobal` / list handoff.

2. **AI_0_1 @ 0x2ff**:
   - tokens: `2d Image Bank`, `Formatted`, `Font ID`
   - best read: **render_curve_or_formatted_bridge**
   - this looks like a bridge from render/image-bank state toward formatted/text styling.

3. **AI_0_1 @ 0x44d**:
   - token: `curved_smaller`
   - best read: **value_trailer_style_bundle**
   - likely a late style/value trailer, but still weakly constrained.

4. **AI_3_3 @ 0x305**:
   - tokens: `GetSaveSize`, `en3d ZBuffered`, `background_path`
   - best read: **variant_render_value_hoist**
   - confirms owner-family semantics are hoisted into a variant render/value zone.

5. **AI_0_4 @ 0x226**:
   - tokens: `Colour`, `s_Version`
   - best read: **variant_trailer_version_bundle**
   - confirms a weaker late-trailer transfer path.

## Honest limit
This pass did **not** fully decode the binary words inside these secondary `A4` records.
What it did do is turn the family from "mysterious extra A4s" into a much tighter semantic map:
canonical owner render bridges vs variant render hoists vs companion incidental value/id pieces.

## Best next move
The most direct follow-up is:

**Stage 103 = render_2dglobal_bridge field correlation pass**

That is the strongest owner-render subtype we currently have.
