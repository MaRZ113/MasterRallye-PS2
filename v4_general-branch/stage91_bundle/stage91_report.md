# Stage 91 report

Stage 91 focused on turning the compact nav refs from Stage 90 into a first
scene-local navigation map for the QuickRace selector/button family.

## Main result

This pass did **not** recover the hidden object-id table that assigns compact
refs like `0x00EC`, `0x00ED`, `0x00F5`, `0x00F8`, and `0x00F9` directly from raw
binary control words.

But it *did* narrow the problem to a practical, structured map:

- `AI_0_1.bin` remains the canonical selector owner.
- `AI_0_2.bin` remains the path/text companion.
- `QuickRace_AI_List_AI_List_02.bin` is the strongest candidate for the shared
  `Down` target (`0x00F5`) because both owner and companion resolve there.
- `AI_3_3.bin` and `QuickRace_AI_0_4_AI_06.bin` are the best pair for the
  second selector-ish branch behind `Right` (`0x00F8` / `0x00F9`).
- `Left Path` uses a shared extended-form block (`1aec0104`) that is much more
  consistent with a back/escape/parent link than with a simple direct member ref.

## Working scene-local nav map (hypothesis layer)

For the canonical owner (`AI_0_1.bin`):

- `Up Path  -> 0x00EC` -> likely self/owner-side selector pair (`AI_0_1.bin`)
- `Right Path -> 0x00F8` -> likely selector pair B / variant owner (`AI_3_3.bin`)
- `Down Path -> 0x00F5` -> likely shared list root (`QuickRace_AI_List_AI_List_02.bin`)
- `Left Path -> 1aec0104` -> likely shared back/escape or parent-scene link

For the companion (`AI_0_2.bin`):

- `Up Path  -> 0x00ED` -> likely companion-side target (`AI_0_2.bin`)
- `Right Path -> 0x00F9` -> likely companion-side variant/text target (`QuickRace_AI_0_4_AI_06.bin`)
- `Down Path -> 0x00F5` -> same shared list root
- `Left Path -> 1aec0104` -> same shared extended back/escape ref

## Why this is still useful

The important shift is that the nav refs are no longer just abstract compact
numbers. They now cluster into a small, interpretable topology:

- a primary selector/text pair (`0x00EC` / `0x00ED`)
- a secondary selector-ish pair (`0x00F8` / `0x00F9`)
- a shared list root (`0x00F5`)
- a shared back/escape link (`1aec0104`)

That is enough to treat QuickRace as a real local navigation graph candidate,
not just a bag of UI tokens.

## Honest limit

The direct proof step is still missing:

- where exactly the compact ref table is stored,
- whether the IDs are scene-local object ordinals, mini-table indices, or packed
  target IDs,
- and whether `0x00EC`/`0x00ED` are self-links or links to sibling rows in a
  higher-level object table.

So Stage 91 should be read as **first scene-local mapping hypotheses**, not as
bit-perfect final decoding.
