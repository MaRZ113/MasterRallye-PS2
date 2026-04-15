# Stage 74 report — first non-video transfer pass (XML-first)

## Scope
This stage pivoted from the mature FMV/media registry into the first non-video class, using XML-like screen entries from `TNG.PAK` as the target.

## What was attempted
1. Recover heuristic XML entry names from `TNG.PAK`
2. Search `TNG.000` for text/UI anchors that semantically match those XML entries
3. Cluster repeated textual regions in `TNG.000`
4. Build a first `PAK XML name -> TNG textual region` bridge

## Main result
Stage 74 **did not** produce an exact XML payload-edge decoder yet.

Stage 74 **did** produce a strong semantic bridge for multiple named XML entries:
- RACEDETAILS2
- OPTIONS
- LANGUAGE
- RACERESULTS
- QUICKRACE
- PROGRESS
- CUPSELECT
- TRAINING
- GAMESELECT2

These names map into repeated textual/frontend banks inside `TNG.000`, with the strongest frontend-rich regions clustered around:
- cluster 2: `0x17c9c381–0x17cd7f1b`
- cluster 6: `0x48a62a9e–0x48aba45b`

## Interpretation
This is a real non-video transfer success, but at the **semantic/region** level rather than the exact-addressing level.

The practical meaning is:
- `TNG.PAK` XML entries are real and address material that is present in `TNG.000`
- `TNG.000` contains repeated frontend/UI text-rich banks
- the next hard problem is not "does XML exist?" but "which local boundary / duplicate-bank rule yields the canonical extract?"

## Why names may still not line up perfectly
This is normal at this stage:
- a `TNG.PAK` XML name can resolve into a repeated or cached textual bank in `TNG.000`
- we have semantic anchors, but not yet a canonical "payload start/end" rule
- some banks appear duplicated or partially repeated, so the first visible hit may not be the canonical instance

## Honest status
- **Success:** first non-video transfer is real
- **Success:** XML-first path looks viable
- **Not yet done:** exact XML entry -> payload boundary decoder
- **Not yet done:** duplicate-bank / canonical-bank resolution

## Recommended next step
**Stage 75 = XML cluster-local boundary / extraction pass**
