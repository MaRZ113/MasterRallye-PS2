Stage 51: 43fc9a value-cluster routing pass

Objective
- continue Stage 50 by resolving 43fc9ae9|7321 not only by field, but by exact repeated value clusters
- separate stable new preview families from false positives, black/degraded windows, and out-of-bounds clusters

Canonical TNG
- size: 1225915283
- sha256: 004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86

Live domain scope
- total 43fc9a hits: 104
- body_prefix 71d0: 5
- body_prefix 7321: 99

Key Stage 51 findings
1. pos024 contains at least two additional stable value-cluster outcomes beyond Stage 50:
   - 0x343FD2F9 (876598009) -> Elf multi-vehicle challenge preview (soft_clean)
   - 0x37F8A59E (939042206) -> GO-overlay track flythrough preview (soft_clean, new family)
2. pos024 also contains a corrupt/false-positive cluster:
   - 0x04387DF9 (70811129) -> rejected
3. Several plausible pos094 clusters are not useful expansions: they are either black/degraded windows, audio-only, or weird-duration false positives. These are now routed as rejected instead of remaining unresolved.
4. A large share of the remaining unresolved mass is actually repeated out-of-bounds value clusters. These are now explicitly marked as deferred_oob instead of being conflated with truly unknown in-bounds candidates.

Record-level primary-route comparison
- Stage 50: {'unresolved': 75, 'clean': 12, 'evidence': 12, 'soft_clean': 5}
- Stage 51: {'deferred_oob': 61, 'clean': 12, 'evidence': 12, 'soft_clean': 12, 'unresolved': 7}

Practical conclusion
- Stage 51 materially reduces ambiguity for 43fc9a by splitting unresolved mass into three honest bins:
  (a) newly routable soft-clean value clusters,
  (b) rejected nonstable/no-video/black clusters,
  (c) deferred out-of-bounds clusters that may need future relative or transformed interpretation.
- The next best step is no longer another blind value pass across all fields; it is a focused follow-up on the new track_flythrough family and on deferred_oob normalization logic.

Recommended next stage
- Stage 52: deferred-oob normalization + track_flythrough family validation pass
