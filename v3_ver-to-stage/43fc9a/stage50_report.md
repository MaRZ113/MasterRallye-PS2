Stage 50: field-aware derivation pass for 43fc9a

Objective
- resolve Stage49 ambiguity on pair 0000010c43fc9ae9 + 7321
- validate 43fc9a against live canonical TNG.000
- promote field/value-derived routes where evidence is strong enough

Canonical TNG
- size: 1225915283
- sha256: 004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86

Live 43fc9a hits
- total hits: 104
- body_prefix 7321: 99
- body_prefix 71d0: 5

Derived routing outcome (record-level primary)
- clean: 12
- soft_clean: 5
- evidence: 12
- unresolved: 75

Key derivations
1. body_prefix 71d0 is no longer pair-only ambiguous in practice: pos020 @ 0x09B16F8C yields a stable audio-backed track/menu preview candidate. Promoted as soft_clean.
2. body_prefix 7321 cannot be solved by pair-only routing. pos024 splits into at least two visually distinct semantic branches:
   - 0x3723B540 -> Fujitsu Siemens track/menu preview
   - 0x34CDEFFC -> challenge preview with two-car backdrop
3. body_prefix 7321 pos094 series remains video-valid but visually degraded/mostly black in current sheets. Kept as evidence, not promoted.
4. body_prefix 7321 pos0a4 remains audio-backed/video-valid but visually degraded. Kept as evidence.

Practical conclusion
- Stage50 partially resolves 43fc9a, but also proves that field-aware routing alone is insufficient for the whole 7321 branch.
- The decisive next step is value-cluster routing for 43fc9a pos024 / pos094 / pos0a4, not another domain scout.

Recommended next stage
- Stage 51: 43fc9a value-cluster routing pass
