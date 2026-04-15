# Stage 78 report

## Scope
Language scene per-member decoder pass over `Language_01.bin` extracted in Stage 76 and member anchors discovered in Stage 77.

## Result
Stage 78 confirms a first practical **per-scene member decoder** pattern for the `Language` scene.

### Strong findings
- The `Language` scene contains 3 literal `<Value Name=...>` members and 3 literal `<AI No=...>` members.
- Member starts are stable, human-readable anchors inside an otherwise mixed XML/binary blob.
- Member bodies are not plain XML. They contain **typed value payloads** and **embedded UI/property blocks**.
- `</Egg>` behaves like a useful **local member boundary marker**.

### Most useful member objects
- Hitable (Bool-like value with embedded UI properties)
- Colour Start (Vector4-like value with property block)
- en2d FileType (Int-like value with Image Bank / 2D properties)
- three AI blocks that look like UI/controller/button subrecords

### Interpretation
The current best working model is:

`scene blob -> literal member anchor (<Value Name / <AI No>) -> typed payload -> embedded property block -> local boundary near </Egg>`

That is enough to claim a first **member-level decoder scaffold** for non-video data, even if a full semantic parser does not exist yet.

## Practical note
This is the first non-video step where extracted sub-objects are small enough to inspect directly without scanning the whole bank.

## Next
Stage 79 should transfer this decoder scaffold from `Language` to a noisier scene such as `RaceResults` or `QuickRace`, to test whether the same member layout generalizes beyond the clean seed scene.
