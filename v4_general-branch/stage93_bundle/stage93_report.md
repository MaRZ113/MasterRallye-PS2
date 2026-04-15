# Stage 93 report

## Goal
Resolve whether QuickRace compact nav refs (`0x00EC`, `0x00ED`, `0x00F5`, `0x00F8`, `0x00F9`) originate in the scene root / AI-list prelude fabric rather than in a carrier-local string or payload layer.

## Result
Stage 93 did **not** find a standalone explicit ordinal table, but it **did** promote a much tighter origin model:

- `0x00F5` is now the strongest **scene-root/shared-list anchor** candidate.
- `0x00EC` / `0x00ED` behave like a paired **owner/companion local ordinal**.
- `0x00F8` / `0x00F9` behave like a paired **secondary owner/companion variant ordinal**.
- `Left Path = 1aec0104` remains an **extended back/escape ref**, not part of the compact u16 family.

## Strongest new evidence
The QuickRace scene root prelude contains the tail bytes `0000f5030000000b`, while `0x00F5` is the only compact ID shared by both `AI_0_1` and `AI_0_2` in their Down slot and already aligns with `QuickRace_AI_List_AI_List_02.bin` as the best list-root candidate.

This does not yet prove a full allocator table, but it is the first time the same compact id cleanly links:

scene root prelude -> shared Down target -> AI_List root candidate

## Practical effect
The compact nav layer is now best explained as:

scene-root / ordinal allocator anchor
-> compact local object ids
-> owner / companion / variant carriers

That is a materially stronger model than Stage 92's "somewhere near the scene root or AI fabric" phrasing.
