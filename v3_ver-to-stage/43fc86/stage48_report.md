# Stage 48 — field-aware generalized media router pass

## Goal
Promote the Stage 46A routing scaffold into a live, field-aware runtime layer using the canonical `TNG.000`,
with Stage 47 `43fc86` promotions folded back into the router.

## Canonical input
- File: `/mnt/data/TNG.000`
- Size: `1225915283` bytes
- SHA256: `004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86`

## Live RID0C scan
- Total `00 00 01 0C` hits: **58875**
- Distinct domains observed: **8829**
- Direct seed-pair routable hits under v2 table: **188**
- Ambiguous hits deferred for field-aware resolution: **22**

## What changed in Stage 48
1. Added a **field-aware routing layer** for `43fc86`.
2. Folded Stage 47 visual/manual correction into taxonomy:
   - `43fc86` multi-car background previews are treated as **challenge_preview**
   - single-road branded previews remain **track_menu_preview**
3. Preserved a strict distinction between:
   - `promoted_clean`
   - `promoted_clean_soft`
   - `secondary_evidence`
   - `rejected_nonstandard`
   - `needs_field_resolution`

## Key finding
`43fc86` cannot be modeled safely by `sig8 + body_prefix` alone.

### Why
Two body-prefix pairs are ambiguous:
- `0000010c43fc86e9 + 4cc3`
- `0000010c43fc86e9 + 521f`

These pairs map to different semantic classes depending on the **matched field**:
- `pos01c` -> track/menu preview lane
- `pos094` -> challenge preview lane
- `pos028` -> secondary challenge evidence lane

This means the next generalized extractor must support:
**sig8 + body_prefix + matched_field** routing when ambiguity is known.

## Live `43fc86` summary
- Total `43fc86` hits in canonical TNG: **35**
- Pair-safe routable hits: **10**
- Ambiguous hits requiring field resolution: **22**
- Residual unknown pair hits (`7243`): **3**

## Promotion consequences
### Safe pair-only rules
- `43fc86e9 + 530f` -> `track_menu_preview_family_01` (promoted clean)
- `43fc86e9 + 6487` -> reject / nonstandard video-like branch

### Field-aware rules required
- `43fc86e9 + 4cc3 + pos01c` -> `track_menu_preview_family_01`
- `43fc86e9 + 4cc3 + pos094` -> `challenge_preview_family_misc`
- `43fc86e9 + 4cc3 + pos028` -> `challenge_preview_family_misc` (secondary evidence)
- `43fc86e9 + 521f + pos01c` -> `track_menu_preview_family_01`
- `43fc86e9 + 521f + pos028` -> `challenge_preview_family_misc` (secondary evidence)

## Stage 48 verdict
Stage 48 succeeded.

The project now has a **live-tested field-aware router specification**.
The generalized extractor is no longer blocked by lack of promotions; it is now blocked by
the need to carry **field context** for ambiguous families.

## Recommended next step
**Stage 49 = generalized extractor runtime pass with field-aware routing**
- feed canonical domain-hit CSVs into the v2 scaffold
- upgrade ambiguous family handling from pair-only to field-aware
- begin emitting standardized statuses:
  `clean / soft_clean / challenge_preview / evidence / rejected / unresolved`
