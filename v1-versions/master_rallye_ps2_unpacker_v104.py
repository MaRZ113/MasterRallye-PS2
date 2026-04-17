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
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

# Known rid0C families already covered by the framework
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

def classify_family(head_len, body_counts, variant_next):
    items = body_counts.most_common()

    def top_next(md5):
        return variant_next[md5].most_common(1)[0] if variant_next[md5] else None
    def is_none(top):
        return top and top[0][0] == 'none'
    def is_0d(top):
        return top and isinstance(top[0][0], tuple) and top[0][0][0] == '0D'

    details = {}

    if head_len == RECORD_LEN:
        if len(items) == 1:
            md5_a, _ = items[0]
            top = top_next(md5_a)
            if is_0d(top):
                details['body_md5'] = md5_a
                details['tail_delta'] = top[0][1]
                return 'fixed_tail_exact_head', details
        if len(items) == 2:
            (md5_a, _), (md5_b, _) = items
            top_a = top_next(md5_a); top_b = top_next(md5_b)
            if (is_none(top_a) and is_0d(top_b)) or (is_none(top_b) and is_0d(top_a)):
                standalone = md5_a if is_none(top_a) else md5_b
                tailed = md5_b if standalone == md5_a else md5_a
                top_t = top_b if tailed == md5_b else top_a
                details['standalone_body_md5'] = standalone
                details['tailed_body_md5'] = tailed
                details['tail_delta'] = top_t[0][1]
                return 'optional_exact_head', details
        return 'exact_head_unknown', details

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
            details['dominant_count'] = max(count_a, count_b)
            details['rare_count'] = min(count_a, count_b)
            return 'optional_companion', details

        if is_0d(top_a) and is_0d(top_b):
            details['variant_a_body_md5'] = md5_a
            details['variant_a_tail_delta'] = top_a[0][1]
            details['variant_b_body_md5'] = md5_b
            details['variant_b_tail_delta'] = top_b[0][1]
            return 'dual_tailed', details

    return 'unknown', details

def main():
    ap = argparse.ArgumentParser(description='BX v104 broad rid0C frontier discovery')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('discover-rid0c-frontier')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--exclude-prefix', type=str, default='0000010c423a')
    p.add_argument('--min-hits', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'discover-rid0c-frontier':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v104 broad rid0C frontier discovery')
    summary.append('======================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'exclude_prefix: {ns.exclude_prefix}')
    summary.append(f'min_hits: {ns.min_hits}')
    summary.append('')

    rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid0c_hits = find_all_mm(mm, RID0C_MARKER)

        family_hits = defaultdict(list)
        for off in rid0c_hits:
            if off + RECORD_LEN > mm.size():
                continue
            rec = bytes(mm[off:off + RECORD_LEN])
            sig8 = rec[:8].hex()
            if sig8 in KNOWN_FAMILIES:
                continue
            if sig8.startswith(ns.exclude_prefix):
                continue
            family_hits[sig8].append((off, rec))

        summary.append(f'total_rid0c_hits: {len(rid0c_hits)}')
        summary.append(f'candidate_families_outside_prefix: {len(family_hits)}')
        summary.append('')

        for sig8, items in sorted(family_hits.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            if len(items) < ns.min_hits:
                continue

            head_len = 8  # exact-head family by definition at sig8 level
            body_counts = Counter()
            variant_next = defaultdict(Counter)

            for off, rec in items:
                body = rec[head_len:]
                body_md5 = hashlib.md5(body).hexdigest()
                body_counts[body_md5] += 1

                before_start = max(0, off - ns.before)
                before = bytes(mm[before_start:off])
                after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])
                _, next_nearest = nearest_markers(before, after, RECORD_LEN)
                if next_nearest:
                    variant_next[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
                else:
                    variant_next[body_md5][('none','')] += 1

            discovered_class, details = classify_family(head_len, body_counts, variant_next)

            row = {
                'sig8': sig8,
                'hits': len(items),
                'head_len': head_len,
                'unique_body_md5': len(body_counts),
                'discovered_class': discovered_class,
                'details': json.dumps(details, ensure_ascii=False),
            }
            rows.append(row)

            summary.append(f'{sig8}: hits={len(items)} variants={len(body_counts)} class={discovered_class}')
            for md5, count in body_counts.most_common():
                top = variant_next[md5].most_common(1)[0] if variant_next[md5] else None
                summary.append(f'  body {md5} :: {count} top_next={top}')
            summary.append('')

        mm.close()

    with (out_dir / 'frontier_discovery.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sig8','hits','head_len','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(rows)

    unknown_rows = [r for r in rows if r['discovered_class'] in ('unknown', 'exact_head_unknown')]
    with (out_dir / 'frontier_unknowns.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sig8','hits','head_len','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(unknown_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'rows': len(rows),
        'unknown_rows': len(unknown_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
