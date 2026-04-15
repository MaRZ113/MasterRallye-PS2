# Stage 58 — targeted PAK entry parser / node-table pass

## Goal
Move from the Stage 57 bridge scaffold into an actual parser-oriented understanding of `TNG.PAK`:
- map the internal sections more concretely
- measure the marker/node fabric starting at `0x1760`
- inspect FMV/PSS entry neighborhoods
- decide whether direct `offset/size` data lives inline with clear path strings or in auxiliary numeric tables

## Inputs
- `/mnt/data/TNG.PAK` (135556 bytes)
- `/mnt/data/TNG.000` (canonical, verified)
- Stage 56 validated media anchors
- Stage 57 semantic/numeric bridge observations

## What was done
1. Re-scanned the entire `TNG.PAK` for clear strings and path-like fragments.
2. Enumerated all `00 00 6c/6e/6f 00` markers as candidate node/record tags.
3. Built a section map with marker and string densities.
4. Built a span catalog from each marker to the next marker in the main region.
5. Extracted FMV/PSS entry neighborhoods and their trailing local metadata.
6. Searched aligned low-level numeric regions for values that normalize near validated TNG media anchors.

## Concrete findings

### 1. The main region really does start at `0x1760`
Section map:
- `0x0000–0x0180`: header / control
- `0x0180–0x0FD3`: dense numeric prelude
- `0x0FD3–0x1760`: early dictionary fragments
- `0x1760–EOF`: main marker-rich node/entry region

The first clean full path at `0x1782` has a prelude containing the same `0x1760` value as the header root/main offset candidate. That makes the `0x1760` anchor stronger, not weaker.

### 2. The main entry region is not a flat directory table
In the main region there are:
- 2557 marker spans
- 256 path-like clear strings

Span stats:
- average span length: 50.64 bytes
- median span length: 39 bytes
- spans with no clear strings: 2078
- spans with exactly one clear string: 414
- spans with 2+ clear strings: 65

This is strong evidence for a **node fabric / trie-like entry layer**, not one neat `struct entry { path, offset, size }` per file.

### 3. `l / n / o` are structural tags, not simple file types
Across clear path entries:
- GXI appears under both `l` and `n`
- PSM appears under both `l` and `n`
- XML appears under `l`, `n`, and a few `o`
- PSS appears under `l`, `n`, and `o`

So the marker class is almost certainly structural/storage-oriented, not just resource-extension typing.

### 4. FMV/PSS entries have repeatable local neighborhoods
For the clear FMV entries, the nearest preceding marker sits roughly **50–127 bytes** before the string.
The last 12 bytes before the path consistently look like:
- two candidate u32 values
- followed by two small trailing u16 control words

Examples:
- `FMV\FUJ3.PSS` → trailing control `0x06ec / 0x0500`
- `FMV\GO2.PSS` → `0x119c / 0x0500`
- `FMV\MICROIDS.PSS` → `0x37cc / 0x0900`
- `FMV\MASTER03.PSS` → `0x09dc / 0x0900`
- `FMV\CHALL04.PSS` → `0x127c / 0x0900`
- `\FMV\TROPHY.PSS` → `0x0c4c / 0x0600`

This is parser-grade evidence that path strings live inside richer node records with stable local metadata.

### 5. The best clue for exact addressing is probably outside the clear strings
When scanning aligned u32 values across the whole file for values that normalize near already validated media anchors, the strongest clusters are not restricted to the clear path slices.
There are dense candidate clusters in the low-offset control regions, especially around:
- `0x0180`
- `0x0328`
- `0x0DEC`

That supports the idea that **the real offset/size bridge is probably in auxiliary numeric tables or node-link tables**, not adjacent to the obvious path strings.

## Practical interpretation
Stage 58 does **not** yield a finished exact parser yet, but it narrows the real problem sharply:

- the clear strings are embedded in node records
- the `l/n/o` markers are structural classes
- the main region is a marker span fabric starting at `0x1760`
- exact absolute addressing likely lives in a lower-level numeric layer that must be joined back to the node fabric

## Deliverables
- `stage58_section_map.csv`
- `stage58_marker_span_catalog.csv`
- `stage58_marker_span_focus.csv`
- `stage58_entry_parser_hypotheses.csv`
- `stage58_fmv_entry_neighborhoods.csv`
- `stage58_numeric_table_clusters.csv`
- `stage58_numeric_table_clusters_top100.csv`
- `stage58_addressing_hypotheses.csv`
- `stage58_next_step_recommendations.csv`

## Recommended next step
**Stage 59 = auxiliary numeric table / root-link pass**

That step should:
1. start from the strongest low-offset numeric clusters
2. test whether those clusters point into node records rooted at `0x1760`
3. try to recover the actual `offset/size` bridge for FMV first
4. then reuse that entry model for XML / GXI / PSB
