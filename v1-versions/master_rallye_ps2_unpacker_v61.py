#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Dict, Tuple

MICROFAMILIES = {
    'c7xx': ['0000010a423fc705', '0000010a423fc7e4'],
    '8x96': ['0000010a423f8f96', '0000010a423f8b96'],
}

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

def load_archetype_records(v59_root: Path) -> Dict[str, bytes]:
    recs = {}
    for p in sorted(v59_root.glob('*.bin')):
        if p.name in ('shared_head.bin', 'shared_tail.bin'):
            continue
        if p.name.endswith('_body.bin'):
            continue
        recs[p.stem.split('_', 1)[1]] = read_bytes(p)
    return recs

def pairwise_prefix_suffix(a: bytes, b: bytes) -> Tuple[int, int]:
    return common_prefix_len([a, b]), common_suffix_len([a, b])

def main():
    ap = argparse.ArgumentParser(description='BX v61 rid0A micro-family splitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-microfamilies')
    p.add_argument('v59_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-microfamilies':
        raise SystemExit(1)

    v59_root: Path = ns.v59_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    recs = load_archetype_records(v59_root)

    summary = []
    summary.append('BX v61 rid0A micro-families')
    summary.append('===========================')
    summary.append(f'v59_root: {v59_root}')
    summary.append('')

    micro_rows = []

    for name, sigs in MICROFAMILIES.items():
        blobs = [recs[s] for s in sigs if s in recs]
        if len(blobs) < 2:
            continue

        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)

        mdir = out_dir / name
        mdir.mkdir(parents=True, exist_ok=True)

        shared_head = blobs[0][:cp]
        shared_tail = blobs[0][len(blobs[0])-cs:] if cs > 0 else b''

        write_bytes(mdir / 'shared_head.bin', shared_head)
        (mdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
        if cs > 0:
            write_bytes(mdir / 'shared_tail.bin', shared_tail)
            (mdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

        summary.append(f'[{name}] members={len(blobs)} shared_head={cp} shared_tail={cs}')
        rows = []

        for sig in sigs:
            if sig not in recs:
                continue
            data = recs[sig]
            body = data[cp: len(data)-cs if cs > 0 else len(data)]
            write_bytes(mdir / f'{sig}.bin', data)
            write_bytes(mdir / f'{sig}_body.bin', body)
            (mdir / f'{sig}.hex.txt').write_text(data.hex(), encoding='utf-8')
            (mdir / f'{sig}_body.hex.txt').write_text(body.hex(), encoding='utf-8')

            subtype = sig[-4:]
            row = {
                'sig8': sig,
                'subtype_hex': subtype,
                'full_len': len(data),
                'shared_head_len': cp,
                'body_len': len(body),
                'shared_tail_len': cs,
                'head16': data[:16].hex(),
                'body_head16': body[:16].hex(),
            }
            rows.append(row)
            micro_rows.append({'microfamily': name, **row})
            summary.append(f'  {sig}: subtype={subtype} body={len(body)} body_head16={body[:16].hex()}')

        # Pairwise compare
        if len(sigs) >= 2 and all(s in recs for s in sigs[:2]):
            a, b = recs[sigs[0]], recs[sigs[1]]
            full_cp, full_cs = pairwise_prefix_suffix(a, b)
            post8_cp, post8_cs = pairwise_prefix_suffix(a[8:], b[8:])
            summary.append(f'  pairwise_full_prefix={full_cp} pairwise_full_suffix={full_cs}')
            summary.append(f'  pairwise_post8_prefix={post8_cp} pairwise_post8_suffix={post8_cs}')

            with (mdir / 'pairwise_meta.json').open('w', encoding='utf-8') as f:
                json.dump({
                    'sig_a': sigs[0],
                    'sig_b': sigs[1],
                    'pairwise_full_prefix': full_cp,
                    'pairwise_full_suffix': full_cs,
                    'pairwise_post8_prefix': post8_cp,
                    'pairwise_post8_suffix': post8_cs,
                }, f, indent=2)

        with (mdir / 'manifest.csv').open('w', encoding='utf-8', newline='') as f:
            fieldnames = ['sig8','subtype_hex','full_len','shared_head_len','body_len','shared_tail_len','head16','body_head16']
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        summary.append('')

    with (out_dir / 'microfamily_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['microfamily','sig8','subtype_hex','full_len','shared_head_len','body_len','shared_tail_len','head16','body_head16']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(micro_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
