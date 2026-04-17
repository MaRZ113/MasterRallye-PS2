#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507
RID0C_MARKER = b'\x00\x00\x01\x0C'

KNOWN_FAMILIES = {
    '0000010c423a4a02',
    '0000010c423a0868',
    '0000010c423ad203',
    '0000010c423ac340',
    '0000010c423a8945',
    '0000010c423a4864',
    '0000010c423a40ae',
    '0000010c423a0063',
    '0000010c423ad082',
    '0000010c423ac0c0',
    '0000010c423ac02c',
    '0000010c423a4b1a',
}

def find_all(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v105 rid0C weak-prefix frontier scout')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('scout-rid0c-frontier-prefixes')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--exclude-prefix', type=str, default='0000010c423a')
    p.add_argument('--prefix-bytes', type=int, default=6, help='sig8 grouping prefix length in bytes')
    p.add_argument('--top-prefixes', type=int, default=16)
    p.add_argument('--top-sig8-per-prefix', type=int, default=8)
    p.add_argument('--min-hit-count', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'scout-rid0c-frontier-prefixes':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    prefix_hex_len = ns.prefix_bytes * 2

    summary = []
    summary.append('BX v105 rid0C weak-prefix frontier scout')
    summary.append('========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'exclude_prefix: {ns.exclude_prefix}')
    summary.append(f'prefix_bytes: {ns.prefix_bytes}')
    summary.append('')

    sig8_hits = Counter()
    sig8_offsets = defaultdict(list)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all(mm, RID0C_MARKER)

        for off in hits:
            if off + RECORD_LEN > mm.size():
                continue
            rec = bytes(mm[off:off + RECORD_LEN])
            sig8 = rec[:8].hex()

            if sig8 in KNOWN_FAMILIES:
                continue
            if sig8.startswith(ns.exclude_prefix):
                continue

            sig8_hits[sig8] += 1
            if len(sig8_offsets[sig8]) < 3:
                sig8_offsets[sig8].append(off)

        mm.close()

    # keep only recurring families
    recurring = {sig8: cnt for sig8, cnt in sig8_hits.items() if cnt >= ns.min_hit_count}

    prefix_families = defaultdict(list)
    for sig8, cnt in recurring.items():
        prefix = sig8[:prefix_hex_len]
        prefix_families[prefix].append((sig8, cnt))

    prefix_rows = []
    for prefix, items in prefix_families.items():
        items_sorted = sorted(items, key=lambda kv: (-kv[1], kv[0]))
        prefix_rows.append({
            'prefix': prefix,
            'family_count': len(items_sorted),
            'total_hits': sum(cnt for _, cnt in items_sorted),
            'top_sig8': items_sorted[0][0],
            'top_sig8_hits': items_sorted[0][1],
        })

    prefix_rows.sort(key=lambda r: (-r['total_hits'], -r['family_count'], r['prefix']))

    with (out_dir / 'prefix_overview.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['prefix','family_count','total_hits','top_sig8','top_sig8_hits'])
        w.writeheader()
        w.writerows(prefix_rows)

    summary.append(f'total_recurring_sig8_outside_423a: {len(recurring)}')
    summary.append(f'unique_prefixes: {len(prefix_rows)}')
    summary.append('')
    summary.append('Top prefixes:')
    for row in prefix_rows[:ns.top_prefixes]:
        summary.append(
            f'  {row["prefix"]}: families={row["family_count"]} total_hits={row["total_hits"]} '
            f'top_sig8={row["top_sig8"]} hits={row["top_sig8_hits"]}'
        )
    summary.append('')

    top_root = out_dir / 'top_prefixes'
    top_root.mkdir(exist_ok=True)

    top_rows = []
    for rank, row in enumerate(prefix_rows[:ns.top_prefixes], 1):
        prefix = row['prefix']
        pdir = top_root / f'{rank:02d}_{prefix}'
        pdir.mkdir(parents=True, exist_ok=True)

        items = sorted(prefix_families[prefix], key=lambda kv: (-kv[1], kv[0]))
        with (pdir / 'sig8_counts.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['sig8','hits'])
            w.writeheader()
            for sig8, cnt in items:
                w.writerow({'sig8': sig8, 'hits': cnt})

        for sig_rank, (sig8, cnt) in enumerate(items[:ns.top_sig8_per_prefix], 1):
            sdir = pdir / f'{sig_rank:02d}_{sig8}'
            sdir.mkdir(parents=True, exist_ok=True)
            for ex_idx, off in enumerate(sig8_offsets[sig8], 1):
                with tng_path.open('rb') as f:
                    f.seek(off)
                    rec = f.read(RECORD_LEN)
                write_bytes(sdir / f'sample_{ex_idx:02d}_0x{off:X}.bin', rec)
                (sdir / f'sample_{ex_idx:02d}_0x{off:X}.hex.txt').write_text(rec.hex(), encoding='utf-8')

            top_rows.append({
                'prefix_rank': rank,
                'prefix': prefix,
                'sig8_rank': sig_rank,
                'sig8': sig8,
                'hits': cnt,
            })

    with (out_dir / 'top_prefix_sig8_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['prefix_rank','prefix','sig8_rank','sig8','hits'])
        w.writeheader()
        w.writerows(top_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'total_recurring_sig8_outside_423a': len(recurring),
        'unique_prefixes': len(prefix_rows),
        'prefix_bytes': ns.prefix_bytes,
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
