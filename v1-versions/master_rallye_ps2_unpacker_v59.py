#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Dict

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def load_top_family_reps(v58_root: Path) -> List[Dict]:
    fam_root = v58_root / 'sig8_families'
    items = []
    for fam_dir in sorted([p for p in fam_root.iterdir() if p.is_dir()]):
        # choose the first representative record as archetype for this sig8 family
        bins = sorted(fam_dir.glob('hit_*.bin'))
        if not bins:
            continue
        rep = bins[0]
        items.append({
            'family_dir': fam_dir.name,
            'sig8': fam_dir.name.split('_', 1)[1],
            'record': read_bytes(rep),
            'rep_name': rep.stem,
        })
    return items

def main():
    ap = argparse.ArgumentParser(description='BX v59 rid0A archetype atlas across exact sig8 families')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-archetype-atlas')
    p.add_argument('v58_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-archetype-atlas':
        raise SystemExit(1)

    root: Path = ns.v58_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    items = load_top_family_reps(root)
    blobs = [x['record'] for x in items]

    cp = common_prefix_len(blobs)
    cs = common_suffix_len(blobs)

    summary = []
    summary.append('BX v59 rid0A archetype atlas')
    summary.append('============================')
    summary.append(f'v58_root: {root}')
    summary.append(f'archetype_count: {len(items)}')
    summary.append(f'cross_family_shared_head: {cp}')
    summary.append(f'cross_family_shared_tail: {cs}')
    summary.append('')

    if items:
        shared_head = blobs[0][:cp]
        write_bytes(out_dir / 'shared_head.bin', shared_head)
        (out_dir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')

        if cs > 0:
            shared_tail = blobs[0][len(blobs[0]) - cs:]
            write_bytes(out_dir / 'shared_tail.bin', shared_tail)
            (out_dir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

    rows = []
    byte_rows = []

    # export archetypes and bodies
    for item in items:
        body = item['record'][cp: len(item['record']) - cs if cs > 0 else len(item['record'])]
        safe = item['family_dir']
        write_bytes(out_dir / f'{safe}.bin', item['record'])
        write_bytes(out_dir / f'{safe}_body.bin', body)
        (out_dir / f'{safe}.hex.txt').write_text(item['record'].hex(), encoding='utf-8')
        (out_dir / f'{safe}_body.hex.txt').write_text(body.hex(), encoding='utf-8')

        rows.append({
            'family_dir': item['family_dir'],
            'sig8': item['sig8'],
            'full_len': len(item['record']),
            'shared_head_len': cp,
            'body_len': len(body),
            'shared_tail_len': cs,
            'head16': item['record'][:16].hex(),
        })

        summary.append(f'{item["sig8"]}: body_len={len(body)} head16={item["record"][:16].hex()}')

    # byte atlas over first 64 bytes
    max_probe = min(64, min(len(x['record']) for x in items)) if items else 0
    for off in range(max_probe):
        row = {'off': off}
        vals = []
        for item in items:
            hx = f'{item["record"][off]:02X}'
            row[item['sig8']] = hx
            vals.append(hx)
        row['uniq'] = len(set(vals))
        byte_rows.append(row)

    with (out_dir / 'family_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['family_dir','sig8','full_len','shared_head_len','body_len','shared_tail_len','head16']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    if byte_rows:
        with (out_dir / 'byte_atlas_first64.csv').open('w', encoding='utf-8', newline='') as f:
            fieldnames = list(byte_rows[0].keys())
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(byte_rows)

    # candidate discriminator offsets after shared head
    cand = []
    for row in byte_rows:
        off = row['off']
        if off < cp:
            continue
        vals = [row[item['sig8']] for item in items]
        uniq = len(set(vals))
        if uniq >= 3:
            cand.append({'off': off, 'uniq_values': uniq})
    with (out_dir / 'candidate_discriminator_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','uniq_values'])
        w.writeheader()
        w.writerows(cand)

    summary.append('')
    summary.append('Candidate discriminator offsets:')
    for r in cand[:20]:
        summary.append(f'  off={r["off"]} uniq_values={r["uniq_values"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
