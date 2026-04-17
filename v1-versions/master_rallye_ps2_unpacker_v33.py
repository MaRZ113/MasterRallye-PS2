#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def find_all(data: bytes, needle: bytes):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def classify_after_prefix(data: bytes, off: int, prefix_len: int, full_tail: bytes, variant_tail: bytes):
    post = data[off + prefix_len : off + prefix_len + max(12, 16)]
    # strongest exact tail heads
    full_head = full_tail[:8]
    var_head  = variant_tail[:12]
    if post.startswith(var_head):
        return 'variant_exact'
    if post.startswith(full_head):
        return 'full_exact'
    # weaker fuzzy anchors
    if len(post) >= 8 and post[4:12] == var_head[4:12]:
        return 'variant_like'
    if len(post) >= 4 and post[1:8] == full_head[1:8]:
        return 'full_like'
    return 'unknown'

def carve(path: Path, off: int, size: int) -> bytes:
    with path.open('rb') as f:
        f.seek(off)
        return f.read(size)

def main():
    ap = argparse.ArgumentParser(description='BX v33 packet locator for TNG.000')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('locate-packets')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v32_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'locate-packets':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v32_root: Path = ns.v32_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix = read_bytes(v32_root / 'shared_packet_prefix.bin')
    full_tail = read_bytes(v32_root / 'full_tail.bin')
    variant_tail = read_bytes(v32_root / 'variant_tail.bin')

    full_size = len(prefix) + len(full_tail)
    variant_size = len(prefix) + len(variant_tail)

    data = read_bytes(tng_path)
    hits = find_all(data, prefix)

    rows = []
    summary = []
    summary.append('BX v33 packet locator')
    summary.append('====================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'prefix_len: {len(prefix)}')
    summary.append(f'full_packet_len: {full_size}')
    summary.append(f'variant_packet_len: {variant_size}')
    summary.append(f'hits: {len(hits)}')
    summary.append('')

    for idx, off in enumerate(hits, 1):
        kind = classify_after_prefix(data, off, len(prefix), full_tail, variant_tail)
        row = {
            'index': idx,
            'offset_hex': f'0x{off:X}',
            'offset': off,
            'kind': kind,
            'full_packet_len': full_size,
            'variant_packet_len': variant_size,
        }
        rows.append(row)
        summary.append(f'{idx:03d}) {row["offset_hex"]} kind={kind}')

        # Carve candidate packets
        hit_dir = out_dir / 'hits' / f'hit_{idx:03d}_{row["offset_hex"]}_{kind}'
        hit_dir.mkdir(parents=True, exist_ok=True)

        shared = carve(tng_path, off, len(prefix))
        (hit_dir / 'shared_packet_prefix.bin').write_bytes(shared)

        full_blob = carve(tng_path, off, full_size)
        variant_blob = carve(tng_path, off, variant_size)
        (hit_dir / 'candidate_full_packet.bin').write_bytes(full_blob)
        (hit_dir / 'candidate_variant_packet.bin').write_bytes(variant_blob)

        # Also expose just tails
        full_tail_blob = carve(tng_path, off + len(prefix), len(full_tail))
        variant_tail_blob = carve(tng_path, off + len(prefix), len(variant_tail))
        (hit_dir / 'candidate_full_tail.bin').write_bytes(full_tail_blob)
        (hit_dir / 'candidate_variant_tail.bin').write_bytes(variant_tail_blob)

        meta = {
            'offset': off,
            'offset_hex': f'0x{off:X}',
            'kind': kind,
            'prefix_len': len(prefix),
            'full_packet_len': full_size,
            'variant_packet_len': variant_size,
        }
        (hit_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

    with (out_dir / 'packet_hits.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','offset_hex','offset','kind','full_packet_len','variant_packet_len'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
