# Stage 60 — second-level bank/page decoding pass

## Goal
Follow Stage 59's direct result: early FMV are reachable through the prelude root-link fabric, but **late FMV** (10 records above `0x10000`) overflow the simple `u16 -> node` model and need a second-stage bank/page interpretation.

## Inputs
- `/mnt/data/TNG.PAK`
- Stage 58 FMV entry neighborhoods
- Stage 59 root-link pair catalog and bridge stats
- canonical `/mnt/data/TNG.000` (used indirectly through the already-validated media atlas)

## What was done
1. Re-parsed **all late FMV/PSS records** in `TNG.PAK` (page index 1).
2. Decomposed their trailing metadata into:
   - `cand_u32_a`
   - `cand_u32_b`
   - `trail_u16_a`
   - `trail_u16_b`
3. Compared the low/high halves of `cand_u32_a/b` against:
   - the Stage 59 prelude root-link table
   - the late FMV string offsets
   - the strongest semantic bridge hints from the media atlas
4. Grouped the late FMV records into **second-level submodels**.

## Concrete findings

### 1. All late FMV entries live on page index 1
Every overflow FMV record now under study sits above `0x10000` in the node region:
late FMV are not arbitrary overflows spread across many pages — this pass sees a coherent **page 1** late-FMV layer.

### 2. A real `page1 + low16 bank/root` submodel exists
Three records expose the same compact pattern in `cand_u32_b`:
- `FMV\CHALL04.PSS` → `0x01005EF8`
- `\FMV\TROPHY.PSS` → `0x01005FB6`
- `FMV\BFGOOD1.PSS` → `0x01005D29`

Interpreting these as **page = 1** plus a **low16 bank/root hint** is the strongest second-level result of Stage 60.

For `CHALL04`, the page-lifted target `0x15EF8` lands only **211 bytes** before the actual string at `0x15FCB`, which is far too neat to dismiss.
For `TROPHY` and `BFGOOD1`, the page-lifted targets do not hit their own strings directly, but they still land in the same shared late-FMV bank/root zone around `0x15Dxx–0x15Fxx`.

### 3. The page-lift low16s sit inside the same root-link cluster family
The low16 roots `0x5D29`, `0x5EF8`, `0x5FB6` all map back into the same Stage 59 prelude cluster family around the `0x5Dxx–0x5Fxx` subtree.
That subtree's nearest clear paths still look semantically unrelated (Turkey/course/GXI content), which strongly suggests we are looking at **structural bank roots**, not user-facing file names.

### 4. Not all late FMV use the same encoding
Stage 60 separates late FMV into at least three submodels:

- **page1_low16_bankroot**
  - `CHALL04`, `TROPHY`, `BFGOOD1`
- **swapped_bankhint_hiword_root**
  - `BAGOO3`, `CHALL06`, `BFGOOD2`
- **alternate_subtype_needs_local_decoder**
  - `MASTER03`, `CREDITS`, `FUJ2`
- plus one **normalized_bankhint_low16_root**
  - `GO3`

So the late FMV problem is now *much* smaller and cleaner:
we do not need one giant decoder, we need a small number of subtype decoders.

### 5. `CHALL04` is now the strongest late-FMV bridge
`CHALL04` combines:
- a strong semantic bridge (`challenge_preview`)
- a page-1 low16 bank/root hint
- and the tightest direct page-lift delta to the actual string

That makes it the best first candidate for the next exact `PAK entry -> TNG window` bridge attempt.

## Practical interpretation
Stage 60 does **not** yet finish the late FMV parser.
But it does move the project from “late FMV need some kind of bank/page step” to:

- page index 1 is real
- a `0x0100xxxx` page-lift encoding exists for one late-FMV subgroup
- the subgroup around `CHALL04/TROPHY/BFGOOD1` is now clearly isolated
- the remaining late FMV split into only a few other local submodels

## Recommended next step
**Stage 61 = page1 subgroup decoder pass**

Focus:
1. start from `CHALL04` as the cleanest late-FMV seed
2. treat `0x0100xxxx` as a page1 bank/root model
3. test whether the page-lift target is:
   - the record itself,
   - a parent node,
   - or a bank header that then references the actual FMV node
4. once that works, transfer the same decoder to `TROPHY` and `BFGOOD1`

That is now the most direct route to the first exact late-FMV `PAK -> TNG` bridge.
