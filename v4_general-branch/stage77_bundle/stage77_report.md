# Stage 77 report

## Scope
Stage 77 focused on intra-scene record discovery inside three canonical scene blobs extracted in Stage 76:
- Language_01.bin
- RaceResults_01.bin
- QuickRace_01.bin

## Main result
Stage 77 found a usable **scene-local member layer**. Instead of only whole-scene blobs, we can now carve repeated local members at tag-level boundaries:
- `<Value Name="...">`
- `<AI_List>`
- `<AI No="...">`

This is the first practical move from **scene blob extraction** toward **per-scene member extraction**.

## Cleanest member candidates
The strongest first-wave members are:
- Language / Hitable
- Language / Colour Start
- Language / en2d FileType
- RaceResults / List*
- RaceResults / UiSelect
- QuickRace / en2d 2dGlobal

## Structural observations
1. All three scenes retain the Stage 76 32-byte big-endian scene header before `<Scene>`.
2. Member starts are not random: most named members begin immediately after short local preludes.
3. Repeated prelude patterns appear, especially:
   - `2b00000010`
   - `20c00005`
   - `8000000b`
4. `RaceResults` and `QuickRace` also contain nested `AI_List` / `AI No` structures, indicating mini-record groups inside the scene blob.

## Practical interpretation
- `Language` is the cleanest first target for a per-member decoder.
- `RaceResults` is next-best for member decoding.
- `QuickRace` is richer but noisier and likely mixes value members with list/index style subrecords.

## Output
Stage 77 produced:
- scene member catalog
- repeated local header pattern catalog
- extracted member blobs and text views
- next-step recommendations
