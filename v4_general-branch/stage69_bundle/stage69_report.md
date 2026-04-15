# Stage 69 report

## Goal
Run the **early_u16 decoder family transfer** pass for the remaining early FMV names that still lacked operational decoders:
- `GO2`
- `FUJ3`
- `ELF3`

## Canonical inputs
- `TNG.PAK`: `/mnt/data/TNG.PAK`
- `TNG.000`: `/mnt/data/TNG.000`
- `TNG.000` sha256: `004AC1676376275BF40C1FD5C1C4A9DCFAAE870BF1A7916434EB73B0B1FAFF86`

## Main result
Stage 69 found **three usable early-family routes**, but they do not all mean the same thing:

- `ELF3` upgraded to **operational_soft_clean**
  - field: `pre_u32_m28`
  - transform: `direct - 0x90000000`
  - nearest pack: `0x38302B25`
  - duration: ~35.69s
  - visual content: coherent Steel Monkeys / track preview material

- `FUJ3` upgraded from evidence to **soft_clean_alias_sibling**
  - field: `pre_u32_m40`
  - transform: `swap16 - 0x60000000`
  - nearest pack: `0x34310A3B`
  - snap delta: 42 bytes
  - visual content: valid preview video, but ELF-branded rather than Fujitsu-labeled

- `GO2` upgraded from evidence to **soft_clean_alias_sibling**
  - field: `pre_u32_m28`
  - transform: `swap16 - 0x20000000`
  - exact pack hit at `0x34554A3F`
  - duration: ~5.16s
  - visual content: valid video, but again ELF-branded rather than GO-labeled

## Honest interpretation
This means the remaining early_u16 family is no longer “unknown”, but it is **not purely single-name exact decoding** either.

The strongest reading now is:

- `ELF3` has a stable operational decoder.
- `GO2` and `FUJ3` are probably **alias/sibling entries** inside a shared early branded-preview family.
- The problem left is therefore mostly **family context / naming precedence**, not raw payload-edge discovery.

## Why this matters
Stage 69 removes the idea that `GO2 / FUJ3 / ELF3` are still raw addressing failures.

They are now:
- one stable operational decoder (`ELF3`)
- two strong sibling/alias decoders (`GO2`, `FUJ3`)

That is enough to stop treating early_u16 as a major blind spot.

## Practical next step
The most useful next move is now:

**Stage 70 = early alias/sibling family resolution pass**

Meaning:
- group `GO2 / FUJ3 / ELF3` as one early branded-preview family
- resolve whether `GO2` and `FUJ3` are alternate labels, sibling members, or bank-level aliases
- then return to the remaining late alternate subtype decoders

## Bigger picture
After Stage 69, the remaining work to reach a truly general unpacker/extractor is:

1. Finish FMV registry stabilization
   - Stage 70: resolve early alias/sibling family
   - then revisit late alternate subtype family (`MASTER03 / CREDITS / FUJ2 / GO3`)

2. Merge all working decoder classes into one registry-driven router
   - exact
   - operational nearest-pack
   - alias/sibling
   - evidence

3. Prove the same `PAK -> TNG` addressing bridge on one **non-video** class
   - preferably `XML`, `GXI`, or `PSB`

4. Wrap the whole thing into a real extractor CLI
   - named lookup from `TNG.PAK`
   - route selection
   - extraction from `TNG.000`
   - manifest/log output

So the honest answer is:
**the project becomes a real general unpacker/extractor after the FMV decoder registry is stabilized and the same bridge survives one non-video resource class.**
