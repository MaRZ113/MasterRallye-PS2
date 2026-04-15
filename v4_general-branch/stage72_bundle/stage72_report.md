# Stage 72 report

Stage 72 = late alternate subtype semantic split.

## Result

### CREDITS
Best candidate remains `pre_u32_m40 - 0x20000000 -> 0x33454A33` (delta 545, ~13.72s).
Contact sheet content is clearly a branded preview clip, not a credits sequence.
Final classification: **soft_clean_alias_sibling** -> `late_branded_preview_family_alt_01`.
Semantic label: **Bago-branded preview sibling / alias**.

### FUJ2
Residual pass found a stronger practical interpretation than Stage 71's evidence-only stance.
Best candidate: `post_u32_p16 - 0x30000000 -> 0x383DEB25` (delta 355, ~10.36s).
Visual similarity is strongest against the branded preview family, especially the `MASTER03` branch.
Final classification: **soft_clean_alias_sibling** -> `early_branded_preview_family_01`.
Semantic label: **Steel Monkeys branded preview sibling / alias**.

## Honest conclusion

Stage 72 did not discover new exact payload edges. What it did was remove the remaining semantic ambiguity around the late alternate subtype and FUJ2 residual case.

After this pass:
- `GO3` remains exact
- `MASTER03` remains operational
- `CREDITS` is no longer treated as a mysterious credits decoder problem; it is a branded preview alias/sibling
- `FUJ2` is no longer a weak blocker; it is an operational sibling/alias classification

This means the next practical move is not another FMV micro-pass but a consolidation step for the FMV registry, followed by the first non-video transfer.
