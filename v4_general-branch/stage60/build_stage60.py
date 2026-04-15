#!/usr/bin/env python3
# Stage 60 reproducer scaffold
# Re-parses late FMV/PSS records in TNG.PAK and classifies them into
# second-level bank/page submodels.

import re, struct, csv, pathlib

pak = pathlib.Path('/mnt/data/TNG.PAK').read_bytes()
pat = re.compile(rb'\\?FMV\\[A-Z0-9_]+\.(?:PSS)')

rows = []
for m in pat.finditer(pak):
    off = m.start()
    if off < 0x10000:
        continue
    last12 = pak[off-12:off]
    a = struct.unpack('<I', last12[:4])[0]
    b = struct.unpack('<I', last12[4:8])[0]
    c = struct.unpack('<H', last12[8:10])[0]
    d = struct.unpack('<H', last12[10:12])[0]
    alo, ahi = a & 0xffff, (a >> 16) & 0xffff
    blo, bhi = b & 0xffff, (b >> 16) & 0xffff
    if bhi == 0x0100:
        model = 'page1_low16_bankroot'
    elif blo in (0x1000, 0x1c00, 0x6000) and 0x5d00 <= bhi <= 0x6100:
        model = 'swapped_bankhint_hiword_root'
    elif 0x5d00 <= blo <= 0x5fff and bhi in (0xb800,):
        model = 'normalized_bankhint_low16_root'
    else:
        model = 'alternate_subtype_needs_local_decoder'
    rows.append({
        'path': m.group().decode(),
        'string_offset_hex': hex(off),
        'cand_u32_a_hex': hex(a),
        'cand_u32_b_hex': hex(b),
        'trail_u16_a_hex': hex(c),
        'trail_u16_b_hex': hex(d),
        'page_index': off >> 16,
        'submodel': model,
    })

out = pathlib.Path('/mnt/data/stage60_bundle/manifests/stage60_second_level_submodels.csv')
out.parent.mkdir(parents=True, exist_ok=True)
with out.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print(f'wrote {len(rows)} rows to {out}')
