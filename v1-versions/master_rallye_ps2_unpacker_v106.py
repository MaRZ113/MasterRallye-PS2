#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507
RID0C_MARKER = b'\x00\x00\x01\x0C'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

def find_all_mm(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

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

def nearest_markers(before: bytes, after: bytes, rec_len: int):
    rows = []
    for rid, marker in RID_MARKERS.items():
        for off in find_all(before, marker):
            rows.append({'rid': rid, 'delta': off - len(before)})
        for off in find_all(after, marker):
            rows.append({'rid': rid, 'delta': rec_len + off})
    rows.sort(key=lambda r: r['delta'])
    prev_rows = [r for r in rows if r['delta'] < 0]
    next_rows = [r for r in rows if r['delta'] > 0]
    return prev_rows[-1] if prev_rows else None, next_rows[0] if next_rows else None

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def classify_exact_head(body_counts, variant_next):
    items = body_counts.most_common()

    def top_next(md5_):
        return variant_next[md5_].most_common(1)[0] if variant_next[md5_] else None
    def is_none(top):
        return top and top[0][0] == 'none'
    def is_0d(top):
        return top and isinstance(top[0][0], tuple) and top[0][0][0] == '0D'

    details = {}

    if len(items) == 1:
        md5_a, _ = items[0]
        top = top_next(md5_a)
        if is_0d(top):
            details['body_md5'] = md5_a
            details['tail_delta'] = top[0][1]
            return 'fixed_tail_exact_head', details
        if is_none(top):
            details['body_md5'] = md5_a
            return 'standalone_exact_head', details
        return 'single_variant_other', details

    if len(items) == 2:
        (md5_a, count_a), (md5_b, count_b) = items
        top_a = top_next(md5_a); top_b = top_next(md5_b)

        if (is_none(top_a) and is_0d(top_b)) or (is_none(top_b) and is_0d(top_a)):
            standalone = md5_a if is_none(top_a) else md5_b
            tailed = md5_b if standalone == md5_a else md5_a
            top_t = top_b if tailed == md5_b else top_a
            details['standalone_body_md5'] = standalone
            details['tailed_body_md5'] = tailed
            details['tail_delta'] = top_t[0][1]
            return 'optional_exact_head', details

        if is_0d(top_a) and is_0d(top_b):
            details['variant_a_body_md5'] = md5_a
            details['variant_a_tail_delta'] = top_a[0][1]
            details['variant_b_body_md5'] = md5_b
            details['variant_b_tail_delta'] = top_b[0][1]
            return 'dual_tailed_exact_head', details

    return 'unknown', details

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v106 weak-prefix class miner for rid0C frontier')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-prefix-class')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--prefix', type=str, default='0000010c4254')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--min-hits', type=int, default=2)
    p.add_argument('--top-export', type=int, default=12)

    ns = ap.parse_args()
    if ns.cmd != 'mine-prefix-class':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v106 weak-prefix class miner')
    summary.append('==============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'prefix: {ns.prefix}')
    summary.append(f'min_hits: {ns.min_hits}')
    summary.append('')

    rows = []
    candidate_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid0c_hits = find_all_mm(mm, RID0C_MARKER)

        sig8_items = defaultdict(list)
        for off in rid0c_hits:
            if off + RECORD_LEN > mm.size():
                continue
            rec = bytes(mm[off:off + RECORD_LEN])
            sig8 = rec[:8].hex()
            if not sig8.startswith(ns.prefix):
                continue
            sig8_items[sig8].append((off, rec))

        summary.append(f'unique_sig8_under_prefix: {len(sig8_items)}')
        summary.append('')

        ranked = sorted(sig8_items.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        export_root = out_dir / 'families'
        export_root.mkdir(exist_ok=True)

        for rank, (sig8, items) in enumerate(ranked, 1):
            if len(items) < ns.min_hits:
                continue

            body_counts = Counter()
            variant_next = defaultdict(Counter)

            for off, rec in items:
                body = rec[8:]
                body_md5 = md5(body)
                body_counts[body_md5] += 1

                before_start = max(0, off - ns.before)
                before = bytes(mm[before_start:off])
                after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])
                _, next_nearest = nearest_markers(before, after, RECORD_LEN)
                if next_nearest:
                    variant_next[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
                else:
                    variant_next[body_md5][('none','')] += 1

            cls, details = classify_exact_head(body_counts, variant_next)

            row = {
                'rank': rank,
                'sig8': sig8,
                'hits': len(items),
                'unique_body_md5': len(body_counts),
                'discovered_class': cls,
                'details': json.dumps(details, ensure_ascii=False),
            }
            rows.append(row)

            summary.append(f'{sig8}: hits={len(items)} variants={len(body_counts)} class={cls}')
            for md5_, count in body_counts.most_common():
                top = variant_next[md5_].most_common(1)[0] if variant_next[md5_] else None
                summary.append(f'  body {md5_} :: {count} top_next={top}')
            summary.append('')

            if cls in ('fixed_tail_exact_head', 'optional_exact_head', 'dual_tailed_exact_head'):
                candidate_rows.append(row)

            if rank <= ns.top_export:
                fdir = export_root / f'{rank:02d}_{sig8}'
                fdir.mkdir(parents=True, exist_ok=True)
                for idx, (off, rec) in enumerate(items[:3], 1):
                    write_bytes(fdir / f'sample_{idx:02d}_0x{off:X}.bin', rec)
                    (fdir / f'sample_{idx:02d}_0x{off:X}.hex.txt').write_text(rec.hex(), encoding='utf-8')

        mm.close()

    with (out_dir / 'prefix_family_classes.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','sig8','hits','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(rows)

    with (out_dir / 'class_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','sig8','hits','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(candidate_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'prefix': ns.prefix,
        'families_total': len(rows),
        'candidate_classes': len(candidate_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
