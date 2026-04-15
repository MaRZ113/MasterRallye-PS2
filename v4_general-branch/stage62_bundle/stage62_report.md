# Stage 62 — selector-transfer decoder pass

## Goal
Upgrade the page1 late-FMV model from a shared subgroup-anchor hypothesis to a reusable member decoder that transfers from the clean seed `FMV\CHALL04.PSS` to `\FMV\TROPHY.PSS` and `FMV\BFGOOD1.PSS`.

## Main result
Stage 62 supports a **compound decoder** for the `page1_low16_bankroot` late-FMV subgroup:

1. `page_index = 1` and `low16(cand_u32_b)` select the shared subgroup anchor.
2. The exact packed word `(trail_u16_b << 16) | trail_u16_a` at `string_offset - 4` acts as a **member key**.
3. This exact packed member key is **unique** in `TNG.PAK` for all three investigated members.

That means late-FMV member resolution is no longer just “shared anchor + nearest local string”.
It is now best modeled as:

**page1 subgroup anchor + exact packed member key -> exact named late-FMV record in `TNG.PAK`**

## Concrete outcomes
- `FMV\CHALL04.PSS` remains the best seed: its page1 anchor lands immediately before its own local subgroup region.
- `\FMV\TROPHY.PSS` now transfers cleanly through the same subgroup family because its exact packed member key `0x06000c4c` occurs only at its own named record.
- `FMV\BFGOOD1.PSS` also transfers cleanly: its exact packed member key `0x0900337c` occurs only at its own named record, even though the anchor lands in a more binary-looking subgroup area.

## Honest limitation
Stage 62 still does **not** produce the final exact `TNG.000` start/size edge for late FMV. The last unresolved piece is the post-member edge from the exact named member record to payload addressing.

## Recommended next step
**Stage 63 = post-member edge decoder pass**

The next pass should start from the exact named member records already resolved here and focus on the remaining candidate u32 fields / sibling numeric tables that may encode the final `TNG.000` window.
