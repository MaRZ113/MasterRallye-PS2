#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def load_bodies(root: Path):
    cdir = root / 'comparative_rid_08'
    bodies = sorted(cdir.glob('*_body.bin'))
    items = []
    for p in bodies:
        fam = 'BXI1' if 'BXI1' in p.stem else 'BXI_'
        items.append({'name': p.stem, 'family': fam, 'data': read_bytes(p)})
    return items

def u16le(buf, off): return struct.unpack_from('<H', buf, off)[0]
def u16be(buf, off): return struct.unpack_from('>H', buf, off)[0]
def u32le(buf, off): return struct.unpack_from('<I', buf, off)[0]
def u32be(buf, off): return struct.unpack_from('>I', buf, off)[0]

def main():
    ap = argparse.ArgumentParser(description='BX v50 custom field miner for rid08 bodies')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('mine-rid08')
    p.add_argument('v47_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()

    root: Path = ns.v47_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    items = load_bodies(root)
    if len(items) < 3:
        raise SystemExit('Need 3 comparative rid08 bodies')

    max_len = max(len(x['data']) for x in items)
    min_len = min(len(x['data']) for x in items)

    # Byte atlas
    byte_rows = []
    candidate_rows = []
    for off in range(max_len):
        vals = []
        present = []
        for it in items:
            if off < len(it['data']):
                vals.append(f'{it["data"][off]:02X}')
                present.append(it['data'][off])
            else:
                vals.append('')
        nonempty = [v for v in vals if v != '']
        uniq = len(set(nonempty))
        row = {'off': off}
        for idx, it in enumerate(items, 1):
            row[f's{idx}_{it["family"]}'] = vals[idx-1]
        row['uniq_nonempty'] = uniq
        byte_rows.append(row)

        # candidate discriminators: two BXI_ equal, BXI1 differs
        if len(items) >= 3:
            a,b,c = items[0], items[1], items[2]
            va = a['data'][off] if off < len(a['data']) else None
            vb = b['data'][off] if off < len(b['data']) else None
            vc = c['data'][off] if off < len(c['data']) else None
            if va is not None and vb is not None and vc is not None:
                if a['family'] == b['family'] == 'BXI_' and va == vb and va != vc:
                    candidate_rows.append({
                        'off': off,
                        'type': 'byte_branch_discriminator',
                        'bxi_value': f'{va:02X}',
                        'bxi1_value': f'{vc:02X}',
                    })

    with (out_dir / 'byte_atlas.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(byte_rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(byte_rows)

    # Word atlas over common length
    word_rows = []
    for off in range(0, min_len - 3, 4):
        vals = []
        for it in items:
            vals.append({
                'u32_le': u32le(it['data'], off),
                'u32_be': u32be(it['data'], off),
                'u16_le': u16le(it['data'], off),
                'u16_be': u16be(it['data'], off),
            })
        row = {'off': off}
        for idx, it in enumerate(items, 1):
            row[f's{idx}_{it["family"]}_u32_le'] = f'0x{vals[idx-1]["u32_le"]:08X}'
            row[f's{idx}_{it["family"]}_u32_be'] = f'0x{vals[idx-1]["u32_be"]:08X}'
        word_rows.append(row)

    with (out_dir / 'word_atlas_u32.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(word_rows[0].keys()) if word_rows else ['off']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(word_rows)

    with (out_dir / 'candidate_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','type','bxi_value','bxi1_value'])
        w.writeheader()
        w.writerows(candidate_rows)

    summary = []
    summary.append('BX v50 rid08 field miner')
    summary.append('========================')
    summary.append(f'samples: {len(items)}')
    for it in items:
        summary.append(f'  {it["family"]} {it["name"]}: len={len(it["data"])} head16={it["data"][:16].hex()}')
    summary.append(f'min_len={min_len} max_len={max_len}')
    summary.append(f'candidate_branch_discriminators={len(candidate_rows)}')
    summary.append('')
    summary.append('Top candidate offsets:')
    for row in candidate_rows[:32]:
        summary.append(f'  off={row["off"]} BXI={row["bxi_value"]} BXI1={row["bxi1_value"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'samples': [{'name': it['name'], 'family': it['family'], 'len': len(it['data'])} for it in items],
        'candidate_offsets': candidate_rows[:128],
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
