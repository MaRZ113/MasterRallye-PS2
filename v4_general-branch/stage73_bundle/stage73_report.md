# Stage 73 — FMV registry consolidation pass

## Goal
Consolidate all named `.PSS` work into a single registry-driven layer that separates:
- canonical named decoder
- operational named decoder
- resolved sibling/alias clip
- evidence-only route
- unresolved name-only entry

## Result
A unified FMV registry was built for all **18** named `TNG.PAK` FMV entries.

### Registry counts
- exact_clean: **5**
- operational_soft_clean: **5**
- resolved sibling/alias: **5**
- evidence_only: **1**
- name_only_unmodeled: **2**

### Practical reading of the registry
- Entries marked **exact_clean** now have parser-grade named payload routes.
- Entries marked **operational** are usable named decoders, but still depend on nearest-pack stabilization.
- Entries marked **sibling/alias** are no longer addressing failures; they resolve into a different branded family member than their raw `TNG.PAK` name suggests.
- Entries marked **evidence_only** still produce weak or degraded media and should not be promoted into the main extractor path.
- Entries marked **name_only_unmodeled** remain catalogued, but not yet bridged.

## Is it normal that names still do not match the visible clips?
Yes.

At this stage `TNG.PAK` provides a **directory identity**, but not every named entry currently resolves to a unique final payload. In several branded early/late families, one named path resolves to a **sibling/alias clip** from the same family bank. That means:
- the entry is real
- the addressing path is real
- but the visible clip still belongs to a neighbouring branded family member

So name/content mismatch is expected whenever the entry is classified as **sibling_alias** rather than canonical/exact.

## Is it normal that some of them still do not show properly?
Also yes.

The remaining reasons are now narrow and explicit:
1. only an **evidence-only** route exists (for example degraded/mostly-black BAGOO3)
2. the decoder reaches a technically valid stream but not a stable named payload
3. the entry is still **name-only** and has not yet reached node/payload bridge level (`CHALL07`, `CHALL09`)

## Outcome
FMV is now mature enough to stop being the main reverse frontier. The registry is strong enough to become the **validation baseline** for the first non-video transfer.

## Recommended next step
**Stage 74 = first non-video transfer pass (XML-first)**

Rationale:
- FMV now provides a stable validation harness
- XML is semantically easier to validate than GXI/PSB
- a successful `PAK -> TNG` bridge on XML will be the first honest step from “very strong media decoder” to a **general unpacker/extractor**
