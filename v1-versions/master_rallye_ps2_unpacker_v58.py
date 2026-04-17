#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Dict

RECORD_SIZE = 253

def carve(src: Path, off: int, size: int = RECORD_SIZE) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def read_classified_hits(path: Path) -> List[Dict]:
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

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

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9,10,13))
    return good / len(data)

def main():
    ap = argparse.ArgumentParser(description='BX v58 rid0A exact-family miner inside one subbranch')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-subbranch')
    p.add_argument('tng_path', type=Path)
    p.add_argument('classified_hits_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--subprefix', type=str, default='0000010a423f')
    p.add_argument('--record-size', type=int, default=253)
    p.add_argument('--max-per-sig8', type=int, default=5)
    p.add_argument('--top-sig8', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'mine-subbranch':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    classified_hits_csv: Path = ns.classified_hits_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = read_classified_hits(classified_hits_csv)
    binary_rows = [r for r in rows if r.get('kind') == 'binary_like']

    subprefix = ns.subprefix.lower()
    sig8_groups = defaultdict(list)

    for r in binary_rows:
        off = int(r['off'])
        idx = int(r['index'])
        rec = carve(tng_path, off, ns.record_size)
        sig8 = rec[:8].hex()
        if not sig8.startswith(subprefix):
            continue
        sig8_groups[sig8].append({
            'index': idx,
            'off': off,
            'off_hex': r['off_hex'],
            'record': rec,
            'printable_ratio': float(r['printable_ratio']),
            'entropy': float(r['entropy']),
        })

    counts = Counter({sig8: len(v) for sig8, v in sig8_groups.items()})

    summary = []
    summary.append('BX v58 rid0A subbranch miner')
    summary.append('============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'subprefix: {subprefix}')
    summary.append(f'sig8_groups: {len(sig8_groups)}')
    summary.append('')

    with (out_dir / 'sig8_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sig8','count'])
        w.writeheader()
        for sig8, cnt in counts.most_common():
            w.writerow({'sig8': sig8, 'count': cnt})

    # export top exact families
    family_meta_rows = []
    reps_dir = out_dir / 'sig8_families'
    reps_dir.mkdir(exist_ok=True)

    for rank, (sig8, cnt) in enumerate(counts.most_common(ns.top_sig8), 1):
        items = sorted(sig8_groups[sig8], key=lambda x: (-x['entropy'], x['index']))[:ns.max_per_sig8]
        fdir = reps_dir / f'{rank:02d}_{sig8}'
        fdir.mkdir(parents=True, exist_ok=True)

        blobs = [x['record'] for x in items]
        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)

        if blobs:
            shared_head = blobs[0][:cp]
            shared_tail = blobs[0][len(blobs[0]) - cs:] if cs > 0 else b''
            write_bytes(fdir / 'shared_head.bin', shared_head)
            (fdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
            if cs > 0:
                write_bytes(fdir / 'shared_tail.bin', shared_tail)
                (fdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

        summary.append(f'{sig8}: total={cnt} reps={len(items)} shared_head={cp} shared_tail={cs}')

        with (fdir / 'representatives.csv').open('w', encoding='utf-8', newline='') as f:
            fieldnames = ['index','off','off_hex','entropy','printable_ratio','len','shared_head_len','shared_tail_len','body_len']
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for item in items:
                body = item['record'][cp: len(item['record']) - cs if cs > 0 else len(item['record'])]
                hit_name = f'hit_{item["index"]:05d}_{item["off_hex"]}'
                write_bytes(fdir / f'{hit_name}.bin', item['record'])
                (fdir / f'{hit_name}.hex.txt').write_text(item['record'].hex(), encoding='utf-8')
                write_bytes(fdir / f'{hit_name}_body.bin', body)
                (fdir / f'{hit_name}_body.hex.txt').write_text(body.hex(), encoding='utf-8')

                row = {
                    'index': item['index'],
                    'off': item['off'],
                    'off_hex': item['off_hex'],
                    'entropy': item['entropy'],
                    'printable_ratio': item['printable_ratio'],
                    'len': len(item['record']),
                    'shared_head_len': cp,
                    'shared_tail_len': cs,
                    'body_len': len(body),
                }
                w.writerow(row)

        family_meta_rows.append({
            'rank': rank,
            'sig8': sig8,
            'total_hits': cnt,
            'representatives': len(items),
            'shared_head_len': cp,
            'shared_tail_len': cs,
        })

    with (out_dir / 'family_meta.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','sig8','total_hits','representatives','shared_head_len','shared_tail_len'])
        w.writeheader()
        w.writerows(family_meta_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
