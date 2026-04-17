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

def main():
    ap = argparse.ArgumentParser(description='BX v95 rid0C class miner across 423a families')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-class')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--prefix', type=str, default='0000010c423a')

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-class':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_root = v74_root / 'sig8_families'
    fam_dirs = sorted([p for p in fam_root.iterdir() if p.is_dir() and p.name.split('_',1)[1].startswith(ns.prefix)])

    summary = []
    summary.append('BX v95 rid0C class miner')
    summary.append('=======================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'v74_root: {v74_root}')
    summary.append(f'family_prefix: {ns.prefix}')
    summary.append(f'families_considered: {len(fam_dirs)}')
    summary.append('')

    family_rows = []
    candidate_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for fam_dir in fam_dirs:
            sig8 = fam_dir.name.split('_',1)[1]
            shared_head = read_bytes(fam_dir / 'shared_head.bin')
            head_len = len(shared_head)

            raw_hits = find_all_mm(mm, shared_head)
            valid_hits = []
            body_counts = Counter()
            next_counts = Counter()
            variant_next = defaultdict(Counter)

            for off in raw_hits:
                if off + RECORD_LEN > mm.size():
                    continue
                rec = bytes(mm[off:off + RECORD_LEN])
                if not rec.startswith(shared_head):
                    continue

                body = rec[head_len:]
                body_md5 = hashlib.md5(body).hexdigest()
                body_counts[body_md5] += 1
                valid_hits.append((off, body_md5))

                before_start = max(0, off - ns.before)
                before = bytes(mm[before_start:off])
                after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])
                _, next_nearest = nearest_markers(before, after, RECORD_LEN)
                if next_nearest:
                    next_counts[(next_nearest['rid'], next_nearest['delta'])] += 1
                    variant_next[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
                else:
                    next_counts[('none','')] += 1
                    variant_next[body_md5][('none','')] += 1

            family_rows.append({
                'family_dir': fam_dir.name,
                'sig8': sig8,
                'head_len': head_len,
                'raw_hits': len(raw_hits),
                'valid_hits': len(valid_hits),
                'unique_body_md5': len(body_counts),
                'top_next': json.dumps([{'rid': rid, 'delta': delta, 'count': count} for (rid, delta), count in next_counts.most_common(3)]),
            })

            summary.append(f'{fam_dir.name}: head_len={head_len} raw={len(raw_hits)} valid={len(valid_hits)} body_variants={len(body_counts)}')
            for body_md5, count in body_counts.most_common():
                summary.append(f'  body {body_md5} :: {count}')
                for (rid, delta), c in variant_next[body_md5].most_common(4):
                    summary.append(f'    next {rid}@{delta} :: {c}')

            # candidate class pattern:
            # exactly 2 body variants, one dominant standalone and one rare next=0D@N
            if len(body_counts) == 2:
                items = body_counts.most_common()
                dominant_md5, dominant_count = items[0]
                rare_md5, rare_count = items[1]

                dominant_top = variant_next[dominant_md5].most_common(1)[0] if variant_next[dominant_md5] else None
                rare_top = variant_next[rare_md5].most_common(1)[0] if variant_next[rare_md5] else None

                def is_none(top):
                    return top and top[0][0] == 'none'
                def is_0d(top):
                    return top and top[0][0][0] == '0D'

                pattern_ok = (
                    dominant_count >= rare_count and
                    ((is_none(dominant_top) and is_0d(rare_top)) or (is_none(rare_top) and is_0d(dominant_top)))
                )

                if pattern_ok:
                    tail_variant_md5 = rare_md5 if is_0d(rare_top) else dominant_md5
                    standalone_variant_md5 = dominant_md5 if is_none(dominant_top) else rare_md5
                    tail_top = rare_top if is_0d(rare_top) else dominant_top
                    tail_delta = tail_top[0][1]
                    candidate_rows.append({
                        'family_dir': fam_dir.name,
                        'sig8': sig8,
                        'head_len': head_len,
                        'standalone_body_md5': standalone_variant_md5,
                        'tailed_body_md5': tail_variant_md5,
                        'tail_delta': tail_delta,
                        'dominant_count': dominant_count,
                        'rare_count': rare_count,
                    })
                    summary.append(f'  >> candidate rule family: tail at {tail_delta}, standalone={standalone_variant_md5}, tailed={tail_variant_md5}')

            summary.append('')

        mm.close()

    with (out_dir / 'family_overview.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_dir','sig8','head_len','raw_hits','valid_hits','unique_body_md5','top_next'])
        w.writeheader()
        w.writerows(family_rows)

    with (out_dir / 'rule_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_dir','sig8','head_len','standalone_body_md5','tailed_body_md5','tail_delta','dominant_count','rare_count'])
        w.writeheader()
        w.writerows(candidate_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'families_considered': len(fam_dirs),
        'families_with_candidates': len(candidate_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
