# Stage 79 report

## Goal
Transfer the first per-member decoder scaffold from the relatively clean `Language` scene to noisier `RaceResults` and `QuickRace` scenes.

## Result
Stage 79 succeeded at the **decoder transfer** level.

The `Language`-derived member scaffold now transfers to `RaceResults` and `QuickRace` in a structured way. The important part is that the transfer is not just textual similarity; the same local object classes recur across scenes:

- `typed_value_member`
- `ui_ai_member`
- `ai_list_transition`
- `compound_ai_block`
- `simple_value_member`

## Practical findings

### Language
Language remains the cleanest reference scene. It still provides the canonical examples for:
- `typed_value_member` (`Hitable`, `Colour Start`, `en2d FileType`)
- `ui_ai_member`

### RaceResults
RaceResults transfers well. The strongest members are:
- `List*`
- `UiSelect`
- `en3d Matrix`
- the first `AI` block

This makes `RaceResults` the best next target for a more exact per-member decoder.

### QuickRace
QuickRace is noisier, but the same member scaffold is clearly present. In particular:
- `en2d 2dGlobal` behaves like a small value member
- `AI_List` is a very small transition/header object
- several `AI` blocks look like compound UI members with embedded `</Egg>` boundaries

## Honest limitation
This is still **member-level carving**, not a fully validated field parser. We can now separate scene-local objects more confidently, but we still do not decode every internal binary payload into fully clean human-readable XML.

## Why this matters
Stage 79 shows that the non-video path is no longer a one-scene curiosity. We now have a believable route:

`bank -> scene -> member-class -> local object extraction`

That is the first real sign that the non-video extractor is becoming general rather than scene-specific.

## Recommended next step
**Stage 80 = RaceResults member-local decoder pass**

RaceResults is the best next step because it is richer than Language, but still cleaner than QuickRace. If that works, the non-video extractor starts to look genuinely reusable.
