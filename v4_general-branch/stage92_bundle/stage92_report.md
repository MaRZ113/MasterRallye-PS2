# Stage 92 report

## Goal
Resolve the likely origin of QuickRace compact navigation refs (`0x00EC`, `0x00ED`, `0x00F5`, `0x00F8`, `0x00F9`) and determine whether they come from a local object-ID namespace, a plain string ref layer, or a separate binary table.

## Result
Stage 92 did **not** isolate a standalone explicit object-ID table, but it **did** tighten the model enough to be useful:

- `AI_0_1.bin` remains the canonical selector owner.
- `AI_0_2.bin` remains the path/text companion.
- `QuickRace_AI_List_AI_List_02.bin` is the shared list root for the Down slot.
- `AI_3_3.bin` and `QuickRace_AI_0_4_AI_06.bin` are the best secondary owner/companion targets for the Right slot.
- `Left Path = 1aec0104` behaves like an extended back/escape ref, not like the same u16 object-ID family used by Up/Right/Down.

## Best current model
The compact refs are best explained as a **scene-local object-ID namespace** or ordinal allocator, probably assigned near the scene root / AI-list fabric, rather than:
- literal string refs
- local start offsets
- direct payload addresses

## Why this matters
This means QuickRace is now close to a genuinely local parser fragment:

owner/companion carriers
→ compact nav slot IDs
→ scene-local object graph candidates

The remaining hard problem is narrow:
find the exact assignment/origin layer for the compact IDs, and separately decode the extended Left Path form.
