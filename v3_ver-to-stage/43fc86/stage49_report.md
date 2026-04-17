# Stage 49 — field-aware generalized extractor runtime pass

## Goal
Upgrade the Stage 48 router into a live runtime layer that can emit field-aware routes on the canonical `TNG.000`.

## Canonical input
- File: `/mnt/data/TNG.000`
- Size: `1225915283` bytes
- SHA256: `004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86`

## Rule catalog
- Pair-only stable rules: **6**
- Field-aware rules: **8**
- Total runtime rules: **14**

## Live watched-hit scan
- Total watched live hits: **213**
- Routed candidate rows emitted: **155**

## Main result
Stage 49 succeeded.

The generalized extractor now has a **live-tested field-aware runtime layer**:
- pair-only stable routing for known clean families
- field-aware routing for ambiguous `43fc86`
- explicit `evidence` and `rejected` lanes
- a bounded ambiguity queue instead of open-ended scout drift

## 43fc86 runtime outcome
- `4cc3 + pos01c` -> `soft_clean` track/menu preview lane
- `4cc3 + pos094` -> `clean` challenge-preview lane
- `4cc3 + pos028` -> `evidence` challenge-preview lane
- `521f + pos01c` -> `clean` track/menu preview lane
- `521f + pos028` -> `evidence` challenge-preview lane
- `530f + pos094` -> `clean` track/menu preview lane
- `6487 + pos008/pos020` -> `rejected` nonstandard lane

## Bounded follow-up queue
- `43fc9ae9 + 7321` remains the clearest next field-aware derivation target.
- `43fc86e9 + 7243` remains a small unresolved live pair.

## Recommended next step
**Stage 50 = 43fc9a field-aware derivation pass**
- resolve `43fc9ae9 + 7321` into stable field-level routes
- fold the result into the Stage 49 runtime layer
- keep `7243` bounded unless it starts paying off again
