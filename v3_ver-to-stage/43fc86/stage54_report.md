Stage 54: targeted ambiguity closure pass

Objective
- close unresolved pair 0000010c43fc86e9 + 7243
- reduce top deferred_oob clusters for 0000010c43fc9ae9 + 7321 (pos020)
- avoid opening new domains; perform bounded closure only

Canonical TNG
- size: 1225915283
- sha256: 004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86

Key outcomes
1. 43fc86 + 7243 is no longer unresolved. A normalized pos028 rule (0x80000000 base) yields a stable multi-vehicle challenge-preview window and is promoted as soft_clean challenge_preview.
2. 43fc86 + 7243 also has corroborating normalized evidence from pos008 (0x60000000 base), visually showing GO/BFGoodrich overlay and parked/off-road vehicle montage. This supports challenge taxonomy but is kept non-primary.
3. Five top deferred 43fc9a pos020 clusters were probed directly. Four produce mostly-black/degraded sheets and are reclassified as rejected degraded_video; one produces fragmentary mosaic output and is reclassified as rejected nonstandard.
4. The only deferred cluster intentionally left open is pos020=2633812737. It remains ambiguous because probe variants produce stream-valid outputs but no reliable visual sheet/semantic anchor.

Primary-route deltas vs Stage 53
- 43fc86 + 7243: unresolved 3 -> soft_clean challenge_preview 3
- 43fc9a deferred_oob: 19 -> 1
- total unresolved: 10 -> 7

Strategic conclusion
- Stage54 successfully converts residual ambiguity into either routable challenge-preview content or bounded rejection buckets.
- The remaining ambiguity is now small and explicit enough to justify a final micro-pass rather than another broad integration stage.

Recommended next step
- Stage 55: final residual micro-closure
  - inspect 43fc9ae9 + 7321 unresolved pair (7)
  - inspect deferred pos020=2633812737 (1)
  - optionally classify 43fc86 pos088 montage evidence if it becomes useful for family atlas work
