# Stage 70 report

## Goal
Run the **early alias/sibling family resolution** pass for the remaining early_u16 family members:
- `GO2`
- `FUJ3`
- `ELF3`

The aim was **not** to discover a new payload-edge, but to resolve family context and naming precedence.

## Canonical inputs
- `TNG.PAK`: `/mnt/data/TNG.PAK`
- `TNG.000`: `/mnt/data/TNG.000`
- inherited operational routes from Stage 69

## Main result
Stage 70 resolves the early_u16 trio as one coherent family:

### `early_branded_preview_family_01`
- **canonical anchor**: `FMV\ELF3.PSS`
- **resolved sibling/alias members**:
  - `FMV\GO2.PSS`
  - `FMV\FUJ3.PSS`

This means the remaining ambiguity in the early_u16 family is **no longer address-related**. It is now resolved as **family context / naming precedence**.

## Why ELF3 is the anchor
`ELF3` remains the strongest stable operational decoder in this family:
- route: `pre_u32_m28`
- transform: `direct - 0x90000000`
- nearest pack: `0x38302B25`
- duration: ~35.69s
- visual content: coherent Steel Monkeys / track-preview material

## Why GO2 and FUJ3 are sibling aliases
Both names resolve to valid operational videos, but the visible payload is ELF-branded rather than GO- or Fujitsu-specific:

- `GO2`
  - route: `pre_u32_m28`
  - transform: `swap16 - 0x20000000`
  - exact pack hit: `0x34554A3F`
  - duration: ~5.16s
  - interpretation: valid sibling clip within the same early branded family

- `FUJ3`
  - route: `pre_u32_m40`
  - transform: `swap16 - 0x60000000`
  - nearest pack: `0x34310A3B`
  - snap delta: 42 bytes
  - duration: ~4.40s
  - interpretation: valid sibling clip within the same early branded family

## Practical registry consequence
Stage 70 recommends the following policy:
- keep the original PAK names (`GO2`, `FUJ3`, `ELF3`) for traceability
- assign all three to one semantic family: `early_branded_preview_family_01`
- prefer `ELF3` as the canonical member when a single family-level representative is needed
- emit `GO2` and `FUJ3` as `sibling_alias` routes rather than pretending they are exact name-to-payload matches

## Honest interpretation
This is an important clean-up step because it removes one more class of ambiguity:
**the early_u16 family is no longer a blind spot in the FMV registry.**

What remains before a truly general unpacker/extractor is not this family, but:
1. the remaining late alternate subtype (`MASTER03 / CREDITS / FUJ2 / GO3`)
2. merging exact + operational + sibling_alias + evidence into one registry-driven router
3. proving the same `PAK -> TNG` bridge on one non-video class (`XML`, `GXI`, or `PSB`)

## Next correct step
**Stage 71 = late alternate subtype decoder pass**

This is now the most practical move, because the early alias/sibling family is resolved enough to stop being a blocker.
