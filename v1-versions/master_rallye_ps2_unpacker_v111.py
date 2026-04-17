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
    ap = argparse.ArgumentParser(description='BX v111 sig7 bucket registry miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-bucket-registry')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--min-hits', type=int, default=4)
    p.add_argument('--min-sig8', type=int, default=2)
    p.add_argument('--top-export', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'mine-bucket-registry':
        raise SystemExit(1)

    tng_path = ns.tng_path
    out_dir = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v111 sig7 bucket registry miner')
    summary.append('=================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'body_prefix_bytes: {ns.body_prefix_bytes}')
    summary.append(f'min_hits: {ns.min_hits}')
    summary.append(f'min_sig8: {ns.min_sig8}')
    summary.append('')

    hit_rows = []
    bucket_hits = defaultdict(list)

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
            bucket = f'{prev_key} || {next_key}'

            tail_sig8 = ''
            tail_md5 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''
                tail_md5 = md5(tail)

            row = {
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': body_md5,
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'bucket': bucket,
                'tail_sig8': tail_sig8,
                'tail_md5': tail_md5,
            }
            hit_rows.append(row)
            bucket_hits[bucket].append(row)

        mm.close()

    with (out_dir / 'hit_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off_hex','sig8','body_md5','body_prefix','prev_key','next_key','bucket','tail_sig8','tail_md5']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(hit_rows)

    registry = []
    export_root = out_dir / 'bucket_candidates'
    export_root.mkdir(exist_ok=True)

    for bucket, rows in bucket_hits.items():
        sig8_counts = Counter(r['sig8'] for r in rows)
        if len(rows) < ns.min_hits or len(sig8_counts) < ns.min_sig8:
            continue

        body_prefix_counts = Counter(r['body_prefix'] for r in rows)
        body_md5_counts = Counter(r['body_md5'] for r in rows)
        tail_sig8_counts = Counter(r['tail_sig8'] for r in rows if r['tail_sig8'])
        tail_md5_counts = Counter(r['tail_md5'] for r in rows if r['tail_md5'])

        prev_key, next_key = bucket.split(' || ', 1)
        class_guess = 'bucket_other'
        if prev_key == 'none' and next_key.startswith('0D@'):
            class_guess = 'cross_sig8_tailed_bucket'
        elif prev_key.startswith('0B@') and next_key == 'none':
            class_guess = 'cross_sig8_prev_link_bucket'
        elif prev_key.startswith('0B@') and next_key.startswith('0D@'):
            class_guess = 'cross_sig8_linked_tailed_bucket'

        registry.append({
            'bucket': bucket,
            'hits': len(rows),
            'unique_sig8': len(sig8_counts),
            'unique_body_prefix': len(body_prefix_counts),
            'unique_body_md5': len(body_md5_counts),
            'unique_tail_sig8': len(tail_sig8_counts),
            'class_guess': class_guess,
            'top_sig8': sig8_counts.most_common(1)[0][0],
            'top_body_prefix': body_prefix_counts.most_common(1)[0][0],
            'top_tail_sig8': tail_sig8_counts.most_common(1)[0][0] if tail_sig8_counts else '',
            'details': json.dumps({
                'sig8_counts': sig8_counts.most_common(),
                'body_prefix_counts': body_prefix_counts.most_common(),
                'tail_sig8_counts': tail_sig8_counts.most_common(),
            }, ensure_ascii=False),
        })

    registry.sort(key=lambda r: (-r['hits'], -r['unique_sig8'], r['bucket']))

    with (out_dir / 'bucket_registry_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket','hits','unique_sig8','unique_body_prefix','unique_body_md5','unique_tail_sig8','class_guess','top_sig8','top_body_prefix','top_tail_sig8','details']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(registry)

    summary.append(f'total_hits_under_sig7: {len(hit_rows)}')
    summary.append(f'bucket_candidates: {len(registry)}')
    summary.append('')
    summary.append('Top bucket candidates:')
    for row in registry[:ns.top_export]:
        summary.append(
            f'  {row["bucket"]}: hits={row["hits"]} unique_sig8={row["unique_sig8"]} '
            f'class={row["class_guess"]} top_sig8={row["top_sig8"]} top_tail={row["top_tail_sig8"]}'
        )
    summary.append('')

    rep_rows = []
    for rank, row in enumerate(registry[:ns.top_export], 1):
        bucket = row['bucket']
        rows = bucket_hits[bucket]
        bdir = export_root / f'{rank:02d}'
        bdir.mkdir(parents=True, exist_ok=True)

        # dump compact member map
        sig8_counts = Counter(r['sig8'] for r in rows)
        body_prefix_counts = Counter(r['body_prefix'] for r in rows)
        tail_sig8_counts = Counter(r['tail_sig8'] for r in rows if r['tail_sig8'])

        with (bdir / 'member_counts.json').open('w', encoding='utf-8') as f:
            json.dump({
                'bucket': bucket,
                'class_guess': row['class_guess'],
                'sig8_counts': sig8_counts,
                'body_prefix_counts': body_prefix_counts,
                'tail_sig8_counts': tail_sig8_counts,
            }, f, indent=2, default=lambda x: dict(x))

        for idx, hit in enumerate(rows[:3], 1):
            off = int(hit['off_hex'], 16)
            with tng_path.open('rb') as f:
                f.seek(off)
                rec = f.read(RECORD_LEN)
            write_bytes(bdir / f'sample_{idx:02d}_{hit["sig8"]}_{hit["off_hex"]}.bin', rec)
            rep_rows.append({
                'bucket_rank': rank,
                'bucket': bucket,
                'sig8': hit['sig8'],
                'off_hex': hit['off_hex'],
                'body_prefix': hit['body_prefix'],
                'tail_sig8': hit['tail_sig8'],
            })

    with (out_dir / 'top_bucket_samples.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket_rank','bucket','sig8','off_hex','body_prefix','tail_sig8']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rep_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'sig7': ns.sig7,
        'total_hits_under_sig7': len(hit_rows),
        'bucket_candidates': len(registry),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
