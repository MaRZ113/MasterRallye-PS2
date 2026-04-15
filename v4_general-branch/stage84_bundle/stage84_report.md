# Stage 84 report

## Title
UiSelect explicit selector/list decoder pass

## Summary
Stage 84 turned the Stage 83 compact field-table scaffold into a more explicit structured decoder for the cleanest RaceResults members: `UiSelect` and `List*`.

The strongest result is `RaceResults.UiSelect`, which now decodes as a selector/list member with:
- member header: `UiSelect / Int`
- inline default value: `0`
- persistence flag: `SaveOptions`
- selector chain: `Index* -> String -> Null -> List`
- path reference: `Frontend/RaceResults/Points`
- layout property: `HeightSpac = 17`
- tail class: `enUIBrowser`

`RaceResults.List*` now decodes as the likely backing list/string member for the same UI block:
- member header: `List* / String`
- inline path reference: `Frontend/RaceResults/Time`
- property/layout chain: `Options -> HeightSpac -> Int -> 17`
- same `enUIBrowser` tail anchor

## Honest status
This is still not a full XML parser. The compact binary control words inside the gap are not yet fully bit/field decoded.
But the member semantics are now explicit enough to support scene-to-scene transfer.

## Practical outcome
The non-video branch now has its first genuinely structured scene-local decoder classes:
- `selector_list_member_v1`
- `list_backing_member_v1`

These are strong enough to carry into another scene without pretending the binary control layer is fully solved.

## Next step
Stage 85 should transfer `selector_list_member_v1` and `list_backing_member_v1` into `QuickRace` and another selector-heavy scene to check whether the same explicit member schema survives outside `RaceResults`.
