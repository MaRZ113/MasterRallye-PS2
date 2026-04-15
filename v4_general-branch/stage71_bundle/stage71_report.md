# Stage 71 report

## Goal
Late alternate subtype decoder pass for:
- `FMV\MASTER03.PSS`
- `FMV\CREDITS.PSS`
- `FMV\GO3.PSS`
- `FMV\FUJ2.PSS`

The goal was to move these entries out of the generic `late_submodel_only` bucket and determine whether they now have exact, operational, alias/sibling, or evidence-only payload routes into `TNG.000`.

## Main result
Stage 71 produced a useful family split:

- `GO3` -> **exact_clean**
- `MASTER03` -> **operational_soft_clean**
- `CREDITS` -> **soft_clean_semantic_mismatch**
- `FUJ2` -> **evidence_only**

This means the late alternate subtype family is no longer blocked primarily on raw addressing. At least two members now have workable routes, and the remaining uncertainty is mostly semantic/contextual rather than purely numeric.

## Per-entry summary

### GO3
Best route:
- field: `pre_u32_m20`
- transform: `direct`
- exact pack start: `0x37DA6B21`
- duration: `17.56s`

This is the strongest Stage 71 result. It behaves like a true exact named payload-edge.

### MASTER03
Best route:
- field: `pre_u32_m16`
- transform: `swap16`
- nearest pack: `0x382B6B25`
- snap delta: `219`
- duration: `18.52s`

This is a stable operational decoder, but not yet an exact-zero edge.

### CREDITS
Best video-bearing route:
- field: `pre_u32_m40`
- transform: `minus_20000000`
- nearest pack: `0x33454A33`
- snap delta: `545`
- duration: `13.72s`

This looks like valid branded preview material, but it does not yet read as an obvious credits sequence. It is therefore treated as a semantic mismatch / sibling-alias case, not as a clean decoder.

### FUJ2
No stable clean transfer was found. Best candidate remains weak:
- field: `pre_u32_m4`
- transform: `direct`
- nearest pack: `0x0500ED3D`
- snap delta: `353`

Current status remains evidence-only.

## Honest conclusion
Stage 71 did not fully close the late alternate subtype family, but it converted it from a broad opaque bucket into a smaller, better-separated set:

- one exact member (`GO3`)
- one operational member (`MASTER03`)
- one semantic/alias problem (`CREDITS`)
- one weak residual (`FUJ2`)

That is enough to say the family is no longer blocked primarily on raw addressing.

## Practical next step
The cleanest next move is **Stage 72 = late alternate subtype semantic split**:
- verify whether `CREDITS` is a real credits FMV or a sibling branded preview alias
- probe `FUJ2` one more time with a smaller, more targeted residual pass
- then fold this family back into the unified named FMV decoder registry
