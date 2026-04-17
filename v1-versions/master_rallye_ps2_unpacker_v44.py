#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def common_prefix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i

def pairwise_best_prefix(blobs: List[bytes]) -> int:
    best = 0
    for i in range(len(blobs)):
        for j in range(i+1, len(blobs)):
            best = max(best, common_prefix_len(blobs[i], blobs[j]))
    return best

def hex_groups(data: bytes, width: int = 16) -> str:
    return ' '.join(f'{b:02X}' for b in data[:width])

def load_rid_bank(root: Path, rid_hex: str):
    rid_dir = root / 'rid_banks' / f'rid_{rid_hex}'
    items = []
    if not rid_dir.exists():
        return items
    for p in sorted(rid_dir.glob('*.bin')):
        items.append({
            'name': p.stem,
            'len': p.stat().st_size,
            'data': read_bytes(p),
        })
    return items

def main():
    ap = argparse.ArgumentParser(description='BX v44 nested field atlas')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('atlas-nested')
    p.add_argument('v43_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'atlas-nested':
        raise SystemExit(1)

    root: Path = ns.v43_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v44 nested field atlas')
    summary.append('========================')
    summary.append(f'v43_root: {root}')
    summary.append('')

    all_rows = []

    for rid_hex in ['07', '08', '09', '0A', '0B']:
        items = load_rid_bank(root, rid_hex)
        if not items:
            continue

        rdir = out_dir / f'rid_{rid_hex}'
        rdir.mkdir(parents=True, exist_ok=True)

        # dump previews / matrix
        matrix_rows = []
        for item in items:
            row = {
                'name': item['name'],
                'len': item['len'],
                'head8': item['data'][:8].hex(),
                'head16': item['data'][:16].hex(),
                'head32_grouped': hex_groups(item['data'], 32),
                'tail16': item['data'][-16:].hex(),
            }
            matrix_rows.append(row)
            all_rows.append({'rid': rid_hex, **row})

        with (rdir / 'matrix.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['name','len','head8','head16','head32_grouped','tail16'])
            w.writeheader()
            w.writerows(matrix_rows)

        # candidate03 reference if present
        ref = next((x for x in items if '03_branch_BXI__hit_025' in x['name']), items[0])
        (rdir / 'reference.bin').write_bytes(ref['data'])
        (rdir / 'reference.hex.txt').write_text(ref['data'].hex(), encoding='utf-8')

        # pairwise best common prefix
        best_prefix = pairwise_best_prefix([x['data'] for x in items])

        summary.append(f'rid {rid_hex}: count={len(items)} best_pairwise_prefix={best_prefix}')
        for row in matrix_rows:
            summary.append(f'  {row["name"]}: len={row["len"]} head8={row["head8"]}')

        # very small interpretation
        if rid_hex == '07':
            summary.append('  note: all samples begin with 00000107 42 5x.. -> likely nested descriptor/start record')
        elif rid_hex == '08':
            summary.append('  note: all samples begin with 00000108 42 5B/5E.. -> likely next nested layer with branch variance')
        elif rid_hex == '09':
            summary.append('  note: rid09 exists in all three candidates but one sample is truncated to 16 bytes')
        elif rid_hex == '0A':
            summary.append('  note: rid0A currently only appears in the richest BXI_ candidate')
        elif rid_hex == '0B':
            summary.append('  note: rid0B is currently a 9-byte terminator-like tail')
        summary.append('')

    with (out_dir / 'atlas.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rid','name','len','head8','head16','head32_grouped','tail16'])
        w.writeheader()
        w.writerows(all_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
