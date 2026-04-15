# Stage 75 report — XML cluster-local boundary / extraction pass

## Scope
This stage moved from semantic XML region bridging into local cluster boundary estimation and first extractable blob generation.

## Main results
- Cluster **6** is the strongest **canonical frontend bank** candidate:
  - boundary: 0x48862000–0x48ac7000
  - size: 2.395 MiB
  - unique keys: 12
  - includes the extra semantic key `MRALLYESTART`
- Clusters **2** and **4** behave like duplicated broad frontend banks with identical key coverage
- Clusters **1**, **3**, and **5** behave like smaller subset banks dominated by `OPTIONS / PROGRESS / QUICKRACE`

## Practical extraction outputs
This stage produced first raw candidate blobs:
- `cluster6_bank.bin` — canonical broad frontend/UI bank candidate
- `cluster2_bank.bin` — duplicate broad frontend bank candidate
- `cluster1_bank.bin` — smaller subset bank candidate

Each extract is accompanied by a printable-string dump for quick inspection.

## Honest status
- Success: cluster-local boundaries are now plausible enough for extraction
- Success: duplicate-bank vs canonical-bank distinction is explicit
- Not yet done: exact per-entry XML blob boundaries
- Not yet done: canonical duplicate selection via structural parser instead of textual density

## Recommended next step
**Stage 76 = XML intra-bank structure / local header pass**
