#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data)

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def classify_blob(data: bytes) -> tuple[str, dict]:
    pr = printable_ratio(data)
    ent = entropy(data)
    ascii_preview = data[:64].decode('latin1', errors='ignore')

    text_markers = [
        '<?xml', '<Egg', 'AI_List', '<Value', 'Frontend', 'MemoryCard',
        'ReplayTheatre', 'Marker Pos', 'Type="'
    ]
    has_text_marker = any(m in ascii_preview for m in text_markers)
    lots_of_angle = data[:128].count(b'<') >= 2 or data[:128].count(b'>') >= 2

    if has_text_marker or (pr > 0.55 and lots_of_angle):
        kind = 'text_like'
    elif pr < 0.30 and ent > 6.5:
        kind = 'binary_like'
    else:
        kind = 'mixed'

    meta = {
        'printable_ratio': round(pr, 6),
        'entropy': round(ent, 6),
        'ascii_preview': ascii_preview,
        'has_text_marker': has_text_marker,
        'lots_of_angle': lots_of_angle,
    }
    return kind, meta

def main():
    ap = argparse.ArgumentParser(description='BX v54 rid0A hit classifier and representative sampler')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('classify-rid0a')
    p.add_argument('tng_path', type=Path)
    p.add_argument('hits_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-size', type=int, default=253)
    p.add_argument('--max-per-class', type=int, default=4)

    ns = ap.parse_args()
    if ns.cmd != 'classify-rid0a':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    hits_csv: Path = ns.hits_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    with hits_csv.open('r', encoding='utf-8', newline='') as f:
        hits = list(csv.DictReader(f))

    rows = []
    by_class = {'binary_like': [], 'text_like': [], 'mixed': []}

    for row in hits:
        off = int(row['off'])
        idx = int(row['index'])
        rec = carve(tng_path, off, ns.record_size)
        kind, meta = classify_blob(rec)

        rows.append({
            'index': idx,
            'off': off,
            'off_hex': row['off_hex'],
            'kind': kind,
            'printable_ratio': meta['printable_ratio'],
            'entropy': meta['entropy'],
            'ascii_preview': meta['ascii_preview'],
        })

        by_class[kind].append({
            'index': idx,
            'off': off,
            'off_hex': row['off_hex'],
            'record': rec,
            'meta': meta,
        })

    # sort representatives
    by_class['binary_like'].sort(key=lambda x: (-x['meta']['entropy'], x['meta']['printable_ratio'], x['index']))
    by_class['text_like'].sort(key=lambda x: (-x['meta']['printable_ratio'], x['index']))
    by_class['mixed'].sort(key=lambda x: (-x['meta']['entropy'], x['index']))

    reps = []
    for kind, arr in by_class.items():
        reps.extend(arr[:ns.max_per_class])

    # write classification csv
    with (out_dir / 'classified_hits.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['index','off','off_hex','kind','printable_ratio','entropy','ascii_preview']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    # write representative set
    rep_rows = []
    reps_dir = out_dir / 'representatives'
    reps_dir.mkdir(exist_ok=True)

    for item in reps:
        kind = next(k for k, arr in by_class.items() if item in arr)
        hdir = reps_dir / f'{kind}_{item["index"]:05d}_{item["off_hex"]}'
        hdir.mkdir(parents=True, exist_ok=True)
        (hdir / 'rid0A_record_253.bin').write_bytes(item['record'])
        (hdir / 'rid0A_record_253.hex.txt').write_text(item['record'].hex(), encoding='utf-8')
        (hdir / 'meta.json').write_text(json.dumps({
            'index': item['index'],
            'off': item['off'],
            'off_hex': item['off_hex'],
            'kind': kind,
            **item['meta']
        }, indent=2), encoding='utf-8')

        rep_rows.append({
            'kind': kind,
            'index': item['index'],
            'off': item['off'],
            'off_hex': item['off_hex'],
            'printable_ratio': item['meta']['printable_ratio'],
            'entropy': item['meta']['entropy'],
        })

    with (out_dir / 'representative_hits.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['kind','index','off','off_hex','printable_ratio','entropy']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rep_rows)

    summary = []
    summary.append('BX v54 rid0A classifier')
    summary.append('======================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'total_hits: {len(hits)}')
    summary.append(f'binary_like: {len(by_class["binary_like"])}')
    summary.append(f'text_like: {len(by_class["text_like"])}')
    summary.append(f'mixed: {len(by_class["mixed"])}')
    summary.append('')
    summary.append('Representative sample set:')
    for r in rep_rows:
        summary.append(
            f'{r["kind"]}: idx={r["index"]} off={r["off_hex"]} '
            f'printable={r["printable_ratio"]:.3f} entropy={r["entropy"]:.3f}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
