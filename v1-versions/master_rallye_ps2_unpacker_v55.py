#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

RECORD_SIZE = 253

def carve(src: Path, off: int, size: int = RECORD_SIZE) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def head_sig(data: bytes, n: int) -> str:
    return data[:n].hex()

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9,10,13))
    return good / len(data)

def main():
    ap = argparse.ArgumentParser(description='BX v55 rid0A binary family grouper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('group-binary-rid0a')
    p.add_argument('tng_path', type=Path)
    p.add_argument('classified_hits_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-size', type=int, default=253)
    p.add_argument('--max-per-family', type=int, default=4)

    ns = ap.parse_args()
    if ns.cmd != 'group-binary-rid0a':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    hits_csv: Path = ns.classified_hits_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    with hits_csv.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))

    binary_rows = [r for r in rows if r.get('kind') == 'binary_like']

    fams = defaultdict(list)
    weak_fams = defaultdict(list)

    for r in binary_rows:
        off = int(r['off'])
        idx = int(r['index'])
        rec = carve(tng_path, off, ns.record_size)

        # strong grouping by first 8 bytes, weak by first 5 bytes (0000010Axx)
        sig8 = head_sig(rec, 8)
        sig5 = head_sig(rec, 5)
        sig6 = head_sig(rec, 6)

        item = {
            'index': idx,
            'off': off,
            'off_hex': r['off_hex'],
            'record': rec,
            'sig5': sig5,
            'sig6': sig6,
            'sig8': sig8,
            'printable_ratio': float(r['printable_ratio']),
            'entropy': float(r['entropy']),
        }
        fams[sig8].append(item)
        weak_fams[sig5].append(item)

    # summaries
    strong_counts = Counter({k: len(v) for k, v in fams.items()})
    weak_counts = Counter({k: len(v) for k, v in weak_fams.items()})

    summary = []
    summary.append('BX v55 rid0A binary family groups')
    summary.append('=================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'binary_like_hits: {len(binary_rows)}')
    summary.append(f'strong_families(sig8): {len(fams)}')
    summary.append(f'weak_families(sig5): {len(weak_fams)}')
    summary.append('')
    summary.append('Top weak families (first 5 bytes):')
    for sig, cnt in weak_counts.most_common(16):
        summary.append(f'  {sig}: {cnt}')
    summary.append('')
    summary.append('Top strong families (first 8 bytes):')
    for sig, cnt in strong_counts.most_common(16):
        summary.append(f'  {sig}: {cnt}')

    # write group tables
    with (out_dir / 'weak_family_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sig5','count'])
        w.writeheader()
        for sig, cnt in weak_counts.most_common():
            w.writerow({'sig5': sig, 'count': cnt})

    with (out_dir / 'strong_family_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sig8','count'])
        w.writeheader()
        for sig, cnt in strong_counts.most_common():
            w.writerow({'sig8': sig, 'count': cnt})

    # representative exports from biggest weak families
    reps_dir = out_dir / 'representatives'
    reps_dir.mkdir(exist_ok=True)
    rep_rows = []

    for fam_rank, (sig5, cnt) in enumerate(weak_counts.most_common(8), 1):
        fam_dir = reps_dir / f'fam_{fam_rank:02d}_{sig5}'
        fam_dir.mkdir(parents=True, exist_ok=True)
        items = sorted(weak_fams[sig5], key=lambda x: (-x['entropy'], x['index']))[:ns.max_per_family]

        for item in items:
            hdir = fam_dir / f'hit_{item["index"]:05d}_{item["off_hex"]}'
            hdir.mkdir(parents=True, exist_ok=True)
            (hdir / 'rid0A_record_253.bin').write_bytes(item['record'])
            (hdir / 'rid0A_record_253.hex.txt').write_text(item['record'].hex(), encoding='utf-8')
            meta = {
                'index': item['index'],
                'off': item['off'],
                'off_hex': item['off_hex'],
                'sig5': item['sig5'],
                'sig6': item['sig6'],
                'sig8': item['sig8'],
                'printable_ratio': item['printable_ratio'],
                'entropy': item['entropy'],
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
            rep_rows.append({
                'family_rank': fam_rank,
                'sig5': sig5,
                'index': item['index'],
                'off_hex': item['off_hex'],
                'sig8': item['sig8'],
                'entropy': item['entropy'],
                'printable_ratio': item['printable_ratio'],
            })

    with (out_dir / 'representative_binary_families.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_rank','sig5','index','off_hex','sig8','entropy','printable_ratio'])
        w.writeheader()
        w.writerows(rep_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
