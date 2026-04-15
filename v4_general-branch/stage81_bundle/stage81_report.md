# Stage 81 report

## Goal
UiSelect / List value payload decoder pass.

## Inputs
Primary RaceResults members from Stage 80:
- RaceResults_01_List_star.bin
- RaceResults_01_UiSelect.bin

Reference Language members from Stage 78:
- Hitable
- Colour Start
- en2d FileType

## Main result
Stage 81 produced the first usable **value/member decoder scaffold** for non-video XML/UI content.

The strongest decoded members are:
- `RaceResults/List*`
- `RaceResults/UiSelect`

For both of them, the pass recovered:
- a stable `<Value Name="...">` anchor
- a declared type (`String` / `Int`)
- inline literal/value evidence
- downstream UI/path/property tokens
- local control/prelude bytes that are reusable as a decoder signature

## Practical interpretation
This is not a full XML parser yet.
But it is now stronger than simple blob carving:

`bank -> scene -> member -> field candidates`

In practice:
- `List*` behaves like a typed string-valued UI member with a frontend path payload
- `UiSelect` behaves like a typed int-valued UI member with persistence and list/index-related payload tokens

## Most useful recovered field hints
### RaceResults/List*
- member_name = `List*`
- declared_type = `String`
- inline literal/path evidence = `Frontend/RaceResults/Time`
- downstream tokens = `Options`, `HeightSpac`

### RaceResults/UiSelect
- member_name = `UiSelect`
- declared_type = `Int`
- inline literal = `0`
- persistence flag = `SaveOptions`
- downstream path evidence = `Frontend/RaceResults/Points`
- downstream tokens = `Index`, `List`, `HeightSpac`

## Transfer result
The same decoding style seen first in `Language` members transfers to `RaceResults` value members:
- value header
- inline literal / path
- local binary control gap
- trailing UI / AI structural tail

## Honest limitations
- Some string fragments are still broken by interleaved binary control bytes.
- Field boundaries inside the binary gap are not fully decoded.
- No canonical numeric field table has been recovered yet.

## Next logical step
**Stage 82 = typed value gap decoder / inline field table pass**

That step should focus on the binary gap between the value header and the trailing UI-property tail,
especially for:
- `RaceResults/List*`
- `RaceResults/UiSelect`
