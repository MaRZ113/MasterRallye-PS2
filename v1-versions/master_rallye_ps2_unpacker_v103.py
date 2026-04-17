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
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

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

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

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
    # returns class_name, details
    items = body_counts.most_common()
    details = {}

    def top_next(md5):
        return variant_next[md5].most_common(1)[0] if variant_next[md5] else None
    def is_none(top):
        return top and top[0][0] == 'none'
    def is_0d(top):
        return top and isinstance(top[0][0], tuple) and top[0][0][0] == '0D'

    if head_len == RECORD_LEN:
        # exact-head classes
        if len(items) == 1:
            md5_a, count_a = items[0]
            top = top_next(md5_a)
            if is_0d(top):
                details['body_md5'] = md5_a
                details['tail_delta'] = top[0][1]
                return 'fixed_tail_exact_head', details
        if len(items) == 2:
            (md5_a, count_a), (md5_b, count_b) = items
            top_a = top_next(md5_a); top_b = top_next(md5_b)
            # one none, one 0D => optional exact-head
            if (is_none(top_a) and is_0d(top_b)) or (is_none(top_b) and is_0d(top_a)):
                standalone = md5_a if is_none(top_a) else md5_b
                tailed = md5_b if standalone == md5_a else md5_a
                top_t = top_b if tailed == md5_b else top_a
                details['standalone_body_md5'] = standalone
                details['tailed_body_md5'] = tailed
                details['tail_delta'] = top_t[0][1]
                return 'optional_exact_head', details
        return 'exact_head_unknown', details

    # head_len < record len, body-bearing families
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
            return 'optional_companion', details
        if is_0d(top_a) and is_0d(top_b):
            details['variant_a_body_md5'] = md5_a
            details['variant_a_tail_delta'] = top_a[0][1]
            details['variant_b_body_md5'] = md5_b
            details['variant_b_tail_delta'] = top_b[0][1]
            return 'dual_tailed', details

    return 'unknown', details

def main():
    ap = argparse.ArgumentParser(description='BX v103 rid0C class discovery miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('discover-rid0c-classes')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--prefix', type=str, default='0000010c423a')

    ns = ap.parse_args()
    if ns.cmd != 'discover-rid0c-classes':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_root = v74_root / 'sig8_families'
    fam_dirs = sorted([p for p in fam_root.iterdir() if p.is_dir() and p.name.split('_',1)[1].startswith(ns.prefix)])

    summary = []
    summary.append('BX v103 rid0C class discovery miner')
    summary.append('===================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'v74_root: {v74_root}')
    summary.append(f'family_prefix: {ns.prefix}')
    summary.append(f'families_considered: {len(fam_dirs)}')
    summary.append(f'known_families_skipped: {len(KNOWN_FAMILIES)}')
    summary.append('')

    rows = []
    unknown_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for fam_dir in fam_dirs:
            sig8 = fam_dir.name.split('_',1)[1]
            if sig8 in KNOWN_FAMILIES:
                continue

            shared_head = read_bytes(fam_dir / 'shared_head.bin')
            head_len = len(shared_head)
            raw_hits = find_all_mm(mm, shared_head)

            body_counts = Counter()
            variant_next = defaultdict(Counter)
            valid_hits = 0

            for off in raw_hits:
                if off + RECORD_LEN > mm.size():
                    continue
                rec = bytes(mm[off:off + RECORD_LEN])
                if not rec.startswith(shared_head):
                    continue
                valid_hits += 1

                body = rec[head_len:] if head_len < RECORD_LEN else b''
                body_md5 = hashlib.md5(body).hexdigest() if body else 'NO_BODY'
                body_counts[body_md5] += 1

                before_start = max(0, off - ns.before)
                before = bytes(mm[before_start:off])
                after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])

                _, next_nearest = nearest_markers(before, after, RECORD_LEN)
                if next_nearest:
                    variant_next[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
                else:
                    variant_next[body_md5][('none','')] += 1

            cls, details = classify_family(head_len, body_counts, variant_next)

            row = {
                'family_dir': fam_dir.name,
                'sig8': sig8,
                'head_len': head_len,
                'raw_hits': len(raw_hits),
                'valid_hits': valid_hits,
                'unique_body_md5': len(body_counts),
                'discovered_class': cls,
                'details': json.dumps(details, ensure_ascii=False),
            }
            rows.append(row)

            summary.append(
                f'{fam_dir.name}: head_len={head_len} raw={len(raw_hits)} valid={valid_hits} '
                f'variants={len(body_counts)} class={cls}'
            )
            for md5, count in body_counts.most_common():
                top = variant_next[md5].most_common(1)[0] if variant_next[md5] else None
                summary.append(f'  body {md5} :: {count} top_next={top}')
            summary.append('')

            if cls == 'unknown' or cls == 'exact_head_unknown':
                unknown_rows.append(row)

        mm.close()

    with (out_dir / 'discovered_classes.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_dir','sig8','head_len','raw_hits','valid_hits','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(rows)

    with (out_dir / 'unknown_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_dir','sig8','head_len','raw_hits','valid_hits','unique_body_md5','discovered_class','details'])
        w.writeheader()
        w.writerows(unknown_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'families_scanned': len(rows),
        'unknown_candidates': len(unknown_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
