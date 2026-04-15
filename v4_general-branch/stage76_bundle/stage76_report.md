# Stage 76 report

## Goal
Move from extractable frontend bank (`cluster6_bank.bin`) to first **local scene/object structure** inside the bank.

## Main result
Stage 76 found **46 scene-like objects** inside `cluster6_bank.bin`, each typically prefixed by a **32-byte big-endian local header** immediately before a `<Scene>` marker.

## Strong findings
- Repeated header magic: `0x3E0D0A11` (first object appears truncated at bank start).
- Repeated structural constants in the 32-byte prelude:
  - `0x0101`
  - `0x200000`
  - trailer `0x0000000B`
- Practical object boundaries work well when slicing from one local header to the next.

## What this means
`cluster6_bank.bin` is not a single XML file. It is a **composite frontend/UI bank** containing many scene objects:
- Language
- RaceResults
- QuickRace
- Progress
- CupSelect
- Training
- VehicleSetup
- GameController
- Debug
and others.

## Duplicate families
Clear duplicate/repeated families were found:
- QuickRace (5)
- GameController (4)
- VehicleSetup (3)
- LoadingScreen (2)
- GameSelect (2)
- Common (2)
- NewStyle (2)
- RaceRetry (2)
- GameOptions (2)
- TitleScreen (2)

This supports the Stage 75 conclusion that multiple frontend/text banks and repeated scene objects exist inside `TNG.000`.

## Practical extraction result
Representative scene blobs were extracted into `/extracts`:
- Language
- RaceResults
- Progress
- QuickRace
- VehicleSetup
- MRallyeStartScreen
- RaceRetry (contains `ReplayTheatre` anchor)
- Debug

## Honest limitation
We still do **not** have a per-entry `PAK -> exact XML object` decoder.
But we now have a much stronger intermediate layer:
**bank -> local scene/object blobs**.

## Next logical step
**Stage 77 = scene-local object field / intra-scene record pass**
- inspect one or two canonical scene blobs (`Language`, `RaceResults`, `QuickRace`)
- look for local offsets, record tables, or repeated object/member headers
- try to move from scene blob extraction to first per-scene object/member extraction
