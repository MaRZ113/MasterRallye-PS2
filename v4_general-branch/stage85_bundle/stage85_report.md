# Stage 85 report

## Goal
Transfer the `selector_list_member_v1` and `list_backing_member_v1` decoders from `RaceResults` into a selector-heavy non-video scene, primarily `QuickRace`.

## Result
Stage 85 is a **partial but real transfer success**.

The transfer did **not** reproduce `RaceResults.UiSelect` as another neat `<Value ...>` object. Instead, in `QuickRace` the same semantics appear to be distributed across **AI/UI members**:
- `QuickRace_AI_0_1_AI_03.bin` -> `selector_button_member_v1`
- `QuickRace_AI_3_3_AI_05.bin` -> `selector_button_member_v1_variant`
- `QuickRace_AI_List_AI_List_02.bin` -> `list_transition_member_v1`
- `QuickRace_AI_0_2_AI_04.bin` -> `path_text_member_v1`
- `QuickRace_en2d_2dGlobal_Value_01.bin` -> `render_config_member_v1`

## Strongest transfer signals
- `Index`, `Null`, `List` tokens migrate from `RaceResults.UiSelect` into `QuickRace` AI members.
- `Font ID`, `Draw Priority`, and `enUI...` tails show the target is still UI-selection logic, just embedded in AI blocks.
- `Frontend/QuickRace/Current...` gives a path-backed UI/text companion branch.
- `AI_List` survives as a compact list-transition anchor.
- `en2d 2dGlobal` remains a render-config companion rather than a selector/list member.

## Honest interpretation
This means the decoder transfer worked **semantically**, but the target scene expresses the same logic using a different local carrier:
- `RaceResults` = cleaner `Value` members
- `QuickRace` = selector/list logic distributed across `AI` blocks

That is still a good result for the general extractor, because it shows the member-class decoder is becoming **scene-general**, not scene-identical.

## Status
- structured_soft_clean: 4
- structured_soft_clean_alias: 1
- evidence_only: 1

## Recommended next move
**Stage 86 = QuickRace AI block local decoder pass**

That is the most direct next step, because it should turn the new `selector_button_member_v1` family into the next genuinely structured non-video decoder.
