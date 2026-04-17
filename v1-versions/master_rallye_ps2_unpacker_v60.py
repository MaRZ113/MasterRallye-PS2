#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def load_archetypes(v59_root: Path):
    manifest = v59_root / 'family_manifest.csv'
    with manifest.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    items = []
    for r in rows:
        fam = r['family_dir']
        p = v59_root / f'{fam}.bin'
        items.append({
            'family_dir': fam,
            'sig8': r['sig8'],
            'data': read_bytes(p),
        })
    return items

def main():
    ap = argparse.ArgumentParser(description='BX v60 rid0A exact-archetype field atlas')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-rid0a-archetype-fields')
    p.add_argument('v59_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-rid0a-archetype-fields':
        raise SystemExit(1)

    root: Path = ns.v59_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    items = load_archetypes(root)
    shared_head = read_bytes(root / 'shared_head.bin')
    head_len = len(shared_head)

    summary = []
    summary.append('BX v60 rid0A exact-archetype fields')
    summary.append('===================================')
    summary.append(f'v59_root: {root}')
    summary.append(f'archetypes: {len(items)}')
    summary.append(f'shared_head_len: {head_len}')
    summary.append(f'shared_head_hex: {shared_head.hex()}')
    summary.append('')

    # Split as head(6) + subtype(2) + body(rest)
    rows = []
    for it in items:
        data = it['data']
        subtype = data[head_len:head_len+2]
        body = data[head_len+2:]
        fam_dir = out_dir / it['family_dir']
        fam_dir.mkdir(parents=True, exist_ok=True)
        write_bytes(fam_dir / 'record.bin', data)
        write_bytes(fam_dir / 'head.bin', data[:head_len])
        write_bytes(fam_dir / 'subtype.bin', subtype)
        write_bytes(fam_dir / 'body.bin', body)
        (fam_dir / 'record.hex.txt').write_text(data.hex(), encoding='utf-8')
        (fam_dir / 'body.hex.txt').write_text(body.hex(), encoding='utf-8')
        rows.append({
            'family_dir': it['family_dir'],
            'sig8': it['sig8'],
            'subtype_hex': subtype.hex(),
            'body_len': len(body),
            'body_head16': body[:16].hex(),
        })
        summary.append(f'{it["sig8"]}: subtype={subtype.hex()} body_len={len(body)} body_head16={body[:16].hex()}')

    with (out_dir / 'archetype_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_dir','sig8','subtype_hex','body_len','body_head16'])
        w.writeheader()
        w.writerows(rows)

    # Byte atlas after shared head
    max_probe = min(64, min(len(x['data']) for x in items) - head_len)
    byte_rows = []
    for rel_off in range(max_probe):
        row = {'rel_off': rel_off, 'abs_off': head_len + rel_off}
        vals = []
        for it in items:
            b = it['data'][head_len + rel_off]
            hx = f'{b:02X}'
            row[it['sig8']] = hx
            vals.append(hx)
        row['uniq'] = len(set(vals))
        byte_rows.append(row)

    with (out_dir / 'post_head_byte_atlas.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(byte_rows[0].keys()) if byte_rows else ['rel_off','abs_off']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(byte_rows)

    # Aligned word atlas over body start
    word_rows = []
    body_min = min(len(x['data']) - (head_len + 2) for x in items)
    for rel_off in range(0, min(64, body_min - 3), 4):
        row = {'body_rel_off': rel_off, 'abs_off': head_len + 2 + rel_off}
        for it in items:
            body = it['data'][head_len+2:]
            u32le = struct.unpack_from('<I', body, rel_off)[0]
            u32be = struct.unpack_from('>I', body, rel_off)[0]
            row[f'{it["sig8"]}_u32_le'] = f'0x{u32le:08X}'
            row[f'{it["sig8"]}_u32_be'] = f'0x{u32be:08X}'
        word_rows.append(row)

    with (out_dir / 'body_word_atlas_u32.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(word_rows[0].keys()) if word_rows else ['body_rel_off','abs_off']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(word_rows)

    # Candidate offsets: positions with subtype-wide diversity after offset 8
    cand = []
    for row in byte_rows:
        if row['rel_off'] < 2:  # subtype itself
            continue
        if row['uniq'] >= 6:
            cand.append({'rel_off': row['rel_off'], 'abs_off': row['abs_off'], 'uniq': row['uniq']})

    with (out_dir / 'candidate_body_discriminators.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rel_off','abs_off','uniq'])
        w.writeheader()
        w.writerows(cand)

    summary.append('')
    summary.append('Subtype bytes (abs off 6-7) are now separated explicitly.')
    summary.append('Candidate body discriminator offsets:')
    for r in cand[:24]:
        summary.append(f'  rel={r["rel_off"]} abs={r["abs_off"]} uniq={r["uniq"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
