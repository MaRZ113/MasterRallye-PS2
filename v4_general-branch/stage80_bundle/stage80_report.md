# Stage 80 report

## Scope
RaceResults member-local decoder pass over `RaceResults_01.bin` extracted from the canonical frontend bank.

## Main result
Stage 80 confirms that `RaceResults` can be split into repeatable **local member objects**, not just scene-level blobs.

Recovered member candidates:
- AI0 browser block around `UiSelect2`
- `List*` typed value member
- `UiSelect` typed value member
- `en3d Matrix` embedded value member
- AI1 text-button / UI block

## Strongest local patterns
- `0d0a202b00000010` before `List*` and `UiSelect`
- `0d0a2020208000000b` before `en3d Matrix`
- `</Egg>` remains a reliable local terminator for top-level objects
- AI objects carry stable UI fragments such as `enUIBrowser`, `UiSelect2`, `Font ID`, `Width`, `Height`, `Drop Shadow`

## Practical meaning
This is the first clean **RaceResults member-local decoder scaffold**:
scene blob -> local member boundary -> member class -> extractable member object

## Best next internal targets
1. `UiSelect`
2. `List*`
3. `en3d Matrix`
4. AI/TextButton block after member transfer stabilizes

## Output
See manifests and `extracts/` in this bundle.