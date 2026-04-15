# Stage 100 report

## Goal
Deeper raw carrier recovery for `AI_3_3` to test whether owner-side `A4` semantics generalize beyond canonical owner `AI_0_1`.

## Result
Stage 100 is successful in a useful way:
- it **does not** recover a second clean nav-slot `A4` tuple in `AI_3_3`
- it **does** show that `A4` is a **broader owner-family binary subrecord marker**, not a nav-slot-only marker
- it **does** place `AI_3_3` inside that broader owner-family via a render/value hoist zone around `0x305`
- it also finds the same broader `A4` family in `AI_0_4`, strengthening the variant-transfer story

## Strongest findings
1. `AI_3_3.bin` contains a single `A4` at `0x305`, positioned **38 bytes after `GetSaveSize`** and **151 bytes before `en3d ZBuffered`**, inside the densest variant-only render/value zone.
2. `AI_0_4.bin` contains another isolated `A4` at `0x226`, after the `Colour/Vector3` tail near trailer/version bytes.
3. `AI_0_1.bin` contains both the known nav-tail `A4` subrecords (`0x123`, `0x12f`) and three additional `A4` occurrences in render/value zones (`0x2ff`, `0x44d`, `0x642`).
4. `AI_0_2.bin` still behaves like a companion (`3E` backlink family); its lone `A4` occurrence is incidental and embedded, not nav-tail ownership.

## Best current interpretation
`A4` marks a broader **owner-family local binary subrecord class** with at least two visible subtypes:
- **nav-tail subtype**: compact owner state / extended owner layout tuple (`AI_0_1`)
- **render/value subtype**: hoisted variant state/layout subblocks (`AI_3_3`, `AI_0_4`, plus secondary zones in `AI_0_1`)

## Practical consequence
`AI_3_3` is now better explained as a **variant owner-family carrier with hoisted A4 semantics**, not as a missing/failed duplicate of canonical nav-tail structure.

## Next step
The next clean step is to cluster the broader `A4` family itself rather than only chase nav tails.
