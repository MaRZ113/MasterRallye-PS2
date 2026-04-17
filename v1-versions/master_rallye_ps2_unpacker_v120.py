#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter
from pathlib import Path

RECORD_LEN = 507
TAIL_LEN = 54
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

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

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

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v120 tailed quarantine branch splitter for 425425**')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('split-tailed-bucket')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--prev', type=str, default='none')
    p.add_argument('--next', type=str, default='0D@1188')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--min-stable-count', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'split-tailed-bucket':
        raise SystemExit(1)

    tng_path = ns.tng_path
    out_dir = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v120 tailed quarantine branch splitter')
    summary.append('========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'target_bucket: {ns.prev} || {ns.next}')
    summary.append(f'body_prefix_bytes: {ns.body_prefix_bytes}')
    summary.append(f'min_stable_count: {ns.min_stable_count}')
    summary.append('')

    rows = []
    branch_counts = Counter()
    sig8_counts = Counter()
    body_prefix_counts = Counter()
    tail_sig8_counts = Counter()

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all_mm(mm, RID0C_MARKER)

        for off in hits:
            if off + RECORD_LEN > mm.size():
                continue

            rec = bytes(mm[off:off + RECORD_LEN])
            sig8 = rec[:8].hex()
            if not sig8.startswith(ns.sig7):
                continue

            body = rec[8:]
            body_md5 = md5(body)
            body_prefix = body[:ns.body_prefix_bytes].hex()

            before_start = max(0, off - ns.before)
            before = bytes(mm[before_start:off])
            after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])

            prev_nearest, next_nearest = nearest_markers(before, after, RECORD_LEN)
            prev_key = f'{prev_nearest["rid"]}@{prev_nearest["delta"]}' if prev_nearest else 'none'
            next_key = f'{next_nearest["rid"]}@{next_nearest["delta"]}' if next_nearest else 'none'

            if prev_key != ns.prev or next_key != ns.next:
                continue

            rel0 = next_nearest['delta'] - RECORD_LEN
            tail = after[rel0:rel0 + TAIL_LEN]
            tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''
            tail_md5 = md5(tail)

            branch_key = f'{sig8} | {body_prefix} | {tail_sig8}'
            branch_counts[branch_key] += 1
            sig8_counts[sig8] += 1
            body_prefix_counts[body_prefix] += 1
            tail_sig8_counts[tail_sig8] += 1

            row = {
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': body_md5,
                'body_prefix': body_prefix,
                'tail_sig8': tail_sig8,
                'tail_md5': tail_md5,
                'branch_key': branch_key,
            }
            rows.append(row)

            hdir = out_dir / 'hits' / f'{sig8}_{off:08X}'
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'rid0C_507.bin', rec)
            write_bytes(hdir / 'tail_candidate_54.bin', tail)
            (hdir / 'meta.json').write_text(json.dumps(row, indent=2), encoding='utf-8')

        mm.close()

    with (out_dir / 'bucket_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off_hex','sig8','body_md5','body_prefix','tail_sig8','tail_md5','branch_key']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    stable_rows = []
    unstable_rows = []
    for branch_key, count in branch_counts.most_common():
        sig8, body_prefix, tail_sig8 = [x.strip() for x in branch_key.split('|')]
        row = {
            'branch_key': branch_key,
            'count': count,
            'sig8': sig8,
            'body_prefix': body_prefix,
            'tail_sig8': tail_sig8,
            'status': 'stable' if count >= ns.min_stable_count else 'unstable',
        }
        if count >= ns.min_stable_count:
            stable_rows.append(row)
        else:
            unstable_rows.append(row)

    with (out_dir / 'stable_branches.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['branch_key','count','sig8','body_prefix','tail_sig8','status']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(stable_rows)

    with (out_dir / 'unstable_branches.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['branch_key','count','sig8','body_prefix','tail_sig8','status']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(unstable_rows)

    proposed_rules = []
    for row in stable_rows:
        proposed_rules.append({
            'name': f'tailed_1188_{row["sig8"][-2:]}_{row["body_prefix"]}',
            'sig7': ns.sig7,
            'prev': ns.prev,
            'next': ns.next,
            'member': {
                row['sig8']: {
                    'body_prefix': row['body_prefix'],
                    'tail_sig8': row['tail_sig8'],
                }
            },
            'count': row['count'],
        })

    (out_dir / 'proposed_rules.json').write_text(json.dumps(proposed_rules, indent=2), encoding='utf-8')

    summary.append(f'matched_hits: {len(rows)}')
    summary.append(f'unique_sig8: {len(sig8_counts)}')
    summary.append(f'unique_body_prefix: {len(body_prefix_counts)}')
    summary.append(f'unique_tail_sig8: {len(tail_sig8_counts)}')
    summary.append(f'stable_branches: {len(stable_rows)}')
    summary.append(f'unstable_branches: {len(unstable_rows)}')
    summary.append('')
    summary.append('sig8 counts:')
    for v, c in sig8_counts.most_common():
        summary.append(f'  {v} :: {c}')
    summary.append('')
    summary.append('body_prefix counts:')
    for v, c in body_prefix_counts.most_common():
        summary.append(f'  {v} :: {c}')
    summary.append('')
    summary.append('tail_sig8 counts:')
    for v, c in tail_sig8_counts.most_common():
        summary.append(f'  {v} :: {c}')
    summary.append('')
    summary.append('Stable branches:')
    for row in stable_rows:
        summary.append(f'  {row["branch_key"]} :: {row["count"]}')
    summary.append('')
    summary.append('Unstable branches:')
    for row in unstable_rows:
        summary.append(f'  {row["branch_key"]} :: {row["count"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'matched_hits': len(rows),
        'stable_branches': len(stable_rows),
        'unstable_branches': len(unstable_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
