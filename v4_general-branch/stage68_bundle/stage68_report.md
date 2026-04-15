# Stage 68 report

## Goal
Run the **early_u16_rootlink payload-edge pass** for the named FMV entries that already had a stable `PAK -> node bridge` but no payload route.

## Canonical inputs
- `TNG.PAK`: `/mnt/data/TNG.PAK`
- `TNG.000`: `/mnt/data/TNG.000`
- `TNG.000` size: `1225915283`
- `TNG.000` sha256: `004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86`

## Main result
This pass found the first **exact named early-FMV payload edge** and two additional **operational early routes**:

- `INV1`: **exact_clean**
  - field: `pre_u32_m24`
  - transform: `direct`
  - target / pack: `0x381F2B25`
  - ffprobe: `mpeg2video`, `512x256`, ~24s

- `MICROIDS`: **operational_soft_clean**
  - field: `pre_u32_m8`
  - transform: `direct - 0xA0000000`
  - target: `0x09640060`
  - nearest pack: `0x0963FEDF`
  - snap delta: `385`
  - ffprobe: `mp2,mpeg2video`, `512x256`, ~48.8s

- `CHALL02`: **operational_soft_clean**
  - field: `pre_u32_m32`
  - transform: `direct`
  - target: `0x04005CC0`
  - nearest pack: `0x04006400`
  - snap delta: `1856`
  - ffprobe: `mp2,mpeg2video`, `512x256`, ~8.8s

Evidence-only candidates remain for:
- `GO2`
- `FUJ3`
- `ELF3`

## Why this matters for the general unpacker/extractor
Early FMV is no longer only a node-bridge family. It now has:
- one **exact named payload decoder**
- two **operational named payload decoders**
- three weaker candidates that can be revisited in a transfer pass

That is enough to justify the next integration milestone:
- Stage 69: transfer the early family decoder logic
- Stage 70: finish the remaining late alternate subtype decoders
- then merge both into one **named decoder registry** that can become the addressing backbone for non-video resource classes.

## What still remains before the general unpacked-extractor
1. **Finish FMV addressing coverage**
   - complete early_u16 family transfer (`FUJ3/GO2/ELF3` and remaining early names)
   - finish late alternate subtype family (`MASTER03/CREDITS/FUJ2/GO3`)

2. **Merge exact + operational rules into one registry-driven `PAK -> TNG` router**
   - one layer for exact decoders
   - one layer for operational nearest-pack decoders
   - one evidence layer kept separate

3. **Prove the addressing bridge on at least one non-video resource class**
   - XML
   - GXI
   - PSB

4. **Wrap all of that in a real unpacker/extractor CLI**
   - named entry lookup from `TNG.PAK`
   - route selection
   - extraction from `TNG.000`
   - output manifests

## When that happens
Not by wall-clock date, but by checkpoint:
- **after Stage 69–70** we should know whether the FMV layer is broad enough to stop being the main unknown
- **after the first non-video transfer pass** the project can honestly be called a *general* unpacker/extractor rather than a strong media decoder
- **after registry + one non-video class + CLI wrapping** it becomes the first practical general tool

So the honest answer is:
the project becomes a real *general* unpacked-extractor **after the FMV registry stabilizes and the same addressing bridge survives one non-video class**.
