#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

COMPONENTS = [
    ('09', 323, '00000109'),
    ('0A', 414, '0000010a'),
    ('0B', 480, '0000010b'),
    ('0C', 507, '0000010c'),
    ('0D', 54,  '0000010d'),
]

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

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

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def main():
    ap = argparse.ArgumentParser(description='BX v72 record family scout for 2088-byte object components')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('scout-record-families')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--max-export-per-family', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'scout-record-families':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v72 record family scout')
    summary.append('==========================')
    summary.append(f'tng_path: {tng_path}')
    summary.append('')

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        top_rows = []

        for rid_hex, rec_len, marker_hex in COMPONENTS:
            marker = bytes.fromhex(marker_hex)
            hits = find_all(mm, marker)

            family_counter = Counter()
            example_hits = defaultdict(list)

            for off in hits:
                if off + rec_len > mm.size():
                    continue
                blob = mm[off:off+rec_len]
                sig8 = blob[:8].hex()
                family_counter[sig8] += 1
                if len(example_hits[sig8]) < ns.max_export_per_family:
                    example_hits[sig8].append((off, bytes(blob)))

            rid_dir = out_dir / f'rid_{rid_hex}'
            rid_dir.mkdir(parents=True, exist_ok=True)

            with (rid_dir / 'sig8_counts.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['sig8','count'])
                w.writeheader()
                for sig8, count in family_counter.most_common():
                    w.writerow({'sig8': sig8, 'count': count})

            fam_rows = []
            for rank, (sig8, count) in enumerate(family_counter.most_common(8), 1):
                fam_dir = rid_dir / f'{rank:02d}_{sig8}'
                fam_dir.mkdir(parents=True, exist_ok=True)
                for idx, (off, blob) in enumerate(example_hits[sig8], 1):
                    write_bytes(fam_dir / f'sample_{idx:02d}_0x{off:X}.bin', blob)
                    (fam_dir / f'sample_{idx:02d}_0x{off:X}.hex.txt').write_text(blob.hex(), encoding='utf-8')
                fam_rows.append({'rank': rank, 'sig8': sig8, 'count': count})

            with (rid_dir / 'top_families.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['rank','sig8','count'])
                w.writeheader()
                w.writerows(fam_rows)

            summary.append(f'rid {rid_hex}: marker_hits={len(hits)} exact_len={rec_len} unique_sig8={len(family_counter)}')
            for sig8, count in family_counter.most_common(8):
                summary.append(f'  {sig8}: {count}')
            summary.append('')

            top_rows.append({
                'rid_hex': rid_hex,
                'marker_hits': len(hits),
                'exact_len': rec_len,
                'unique_sig8': len(family_counter),
                'top_sig8': family_counter.most_common(1)[0][0] if family_counter else '',
                'top_sig8_count': family_counter.most_common(1)[0][1] if family_counter else 0,
            })

        mm.close()

    with (out_dir / 'family_overview.csv').open('w', encoding='utf-8', newline='') as f_csv:
        w = csv.DictWriter(f_csv, fieldnames=['rid_hex','marker_hits','exact_len','unique_sig8','top_sig8','top_sig8_count'])
        w.writeheader()
        w.writerows(top_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
