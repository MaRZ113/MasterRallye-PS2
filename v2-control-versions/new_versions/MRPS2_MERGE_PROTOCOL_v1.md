# MRPS2 reproducibility protocol

## Purpose
This document defines the **official workflow** for building the Master Rallye PS2 unpacker without drifting into optimistic or non-reproducible percentages.

## Canonical input
Use exactly one canonical input:
- Asset: `TNG.000`
- Carrier: `TNG-000_1_full.zip`
- ZIP entry CRC32: `C740B8AA`
- Size: `1225915283` bytes
- SHA-256: `004ac1676376275bf40c1fd5c1c4a9dcfaae870bf1a7916434eb73b0b1faff86`

No summary, percentage, or merged-pack claim is official unless it was produced against this canonical input.

## Official checkpoint
Current official baseline:
- 43fc family: `master_rallye_ps2_rulepack_43fc_family_reconciled_v210.json`
- 43fc manifest: `master_rallye_ps2_rulepack_43fc_family_reconciled_v210_manifest.json`
- 43fc summary: `v210_cov_43fc_family_reconciled/summary.txt`
- 425425 standalone: `master_rallye_ps2_rulepack_425425_v141.json`
- 425425 summary: `v141_cov_full/summary.txt`

This means the current official tracked baseline is:
- 43fc family: 2104/3534 = 0.5954
- 425425 domain: 653/653 = 1.0000
- Combined tracked scope: 2757/4187 = 0.6585

## Status model
Every domain must live in exactly one status bucket:
- **lab**: explored locally, not official
- **validated**: standalone domain coverage reproduced on canonical input
- **merged**: included in the current reconciled merged pack and verified by a full merged run
- **deprecated**: historical rulepack kept for reference but not trusted as current truth

A domain is **not official** just because it once hit 100% locally.

## Acceptance rule for a new domain
A domain is promoted into the official percentage only if all of these are true:
1. The domain rulepack exists on disk.
2. The domain reproduces its standalone coverage on the canonical input.
3. The domain is added to the merged pack manifest.
4. The merged pack is rerun on the canonical input.
5. New summary files are saved.
6. The checkpoint JSON/manifest are updated.

If step 4 or 5 is missing, the domain stays in **lab** or **validated**, not **merged**.

## Mandatory outputs for each official update
Every official update must produce:
- merged rulepack JSON
- merged manifest JSON
- full coverage summary
- residual-domain report / scout
- updated domain registry snapshot

## What must never happen again
- Do not quote percentages from chat memory.
- Do not mix old local victories with a newer merged pack.
- Do not change the official percentage based on a standalone domain run.
- Do not trust a domain merely because a historical file exists.

## Practical workflow
1. Rebuild or verify canonical `TNG.000`.
2. Verify hashes against `MRPS2_CANONICAL_INPUT.json`.
3. Pick exactly one target domain or one reconciliation task.
4. Run standalone domain validation.
5. If valid, merge it into the current official manifest.
6. Run the merged pack on the canonical input.
7. Save all artifacts.
8. Update the checkpoint JSON and domain registry.

## Recommendation
Use the **latest reconciled checkpoint** as the only source of truth for official percentages. Treat everything else as experimental until merged and rerun.
