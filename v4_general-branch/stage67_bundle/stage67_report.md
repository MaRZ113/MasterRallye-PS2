# Stage 67 — operational named-FMV decoder registry / decision pivot

## Goal
Convert the accumulated FMV reverse work into a **named decoder registry** for `TNG.PAK -> TNG.000`, and decide what the most practical next generalization step should be.

## Inputs
- canonical `/mnt/data/TNG.000`
- local `TNG.PAK`
- Stage 59 early root-link bridge
- Stage 63 exact late-FMV bridge
- Stage 66 late-submodel stabilization

## Result summary
Stage 67 does not chase one more weak late-FMV salvage. Instead, it formalizes the current state of the named FMV layer as a practical decoder baseline.

### Named FMV inventory
A heuristic scan of `TNG.PAK` currently yields **18 named `.PSS` paths**.

### Current operational picture
Out of 18 named FMV entries:
- **5** now have an **operational named decoder**
  - `CHALL04`, `TROPHY`, `BFGOOD1` → **exact_clean**
  - `BFGOOD2` → **stabilized_soft_clean**
  - `CHALL06` → **verified_sibling_alias**
- **6** have a stable **PAK->node bridge only** (`early_u16_rootlink`)
  - `FUJ3`, `GO2`, `MICROIDS`, `CHALL02`, `INV1`, `ELF3`
- **4** are **late submodels only**
  - `MASTER03`, `CREDITS`, `GO3`, `FUJ2`
- **1** remains **evidence only**
  - `BAGOO3`
- **2** are currently **name-only / unmodeled**
  - `CHALL07`, `CHALL09`

### Main decision
The most practical next step is **not** more weak late-FMV cleanup.  
The biggest remaining payoff is now the **early_u16_rootlink** family: six named FMVs already have strong `PAK -> node` bridges but no exact/operational payload-edge. Solving even part of that family would expand named operational coverage much faster than squeezing more out of BAGOO3.

## Practical conclusion
Stage 67 officially fixes the project direction:

1. Treat the FMV layer as **operationally mature enough** to use as an addressing validation baseline.
2. Stop spending the main thread on weak late-FMV salvage.
3. Move next to:
   - **Stage 68 = early_u16_rootlink payload-edge pass**
   - then likely **Stage 69 = alternate subtype decoder pass**

This is the practical pivot from "late-FMV cleanup" back into broader `PAK -> TNG` decoder generalization.
