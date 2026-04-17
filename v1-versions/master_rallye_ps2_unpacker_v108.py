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

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def main():
    ap = argparse.ArgumentParser(description='BX v108 sig7 structural bucket miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-sig7-buckets')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=4)
    p.add_argument('--top-buckets', type=int, default=12)

    ns = ap.parse_args()
    if ns.cmd != 'mine-sig7-buckets':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    body_prefix_hex_len = ns.body_prefix_bytes * 2

    summary = []
    summary.append('BX v108 sig7 structural bucket miner')
    summary.append('===================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'body_prefix_bytes: {ns.body_prefix_bytes}')
    summary.append('')

    hit_rows = []
    bucket_hits = defaultdict(list)
    bucket_sig8 = defaultdict(set)
    bucket_body_prefix = defaultdict(set)
    prefix_hits = defaultdict(list)
    exact_body_sharing = defaultdict(set)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid0c_hits = find_all_mm(mm, RID0C_MARKER)

        for off in rid0c_hits:
            if off + RECORD_LEN > mm.size():
                continue
            rec = bytes(mm[off:off+RECORD_LEN])
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

            row = {
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': body_md5,
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'bucket': bucket,
            }
            hit_rows.append(row)
            bucket_hits[bucket].append(row)
            bucket_sig8[bucket].add(sig8)
            bucket_body_prefix[bucket].add(body_prefix)
            prefix_hits[body_prefix].append(row)
            exact_body_sharing[body_md5].add(sig8)

        mm.close()

    # per-hit manifest
    with (out_dir / 'hit_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off_hex','sig8','body_md5','body_prefix','prev_key','next_key','bucket']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(hit_rows)

    # structural buckets
    bucket_rows = []
    for bucket, rows in bucket_hits.items():
        bucket_rows.append({
            'bucket': bucket,
            'hits': len(rows),
            'unique_sig8': len(bucket_sig8[bucket]),
            'unique_body_prefix': len(bucket_body_prefix[bucket]),
            'top_sig8': Counter(r['sig8'] for r in rows).most_common(1)[0][0],
            'top_body_prefix': Counter(r['body_prefix'] for r in rows).most_common(1)[0][0],
        })
    bucket_rows.sort(key=lambda r: (-r['hits'], -r['unique_sig8'], r['bucket']))

    with (out_dir / 'structural_buckets.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket','hits','unique_sig8','unique_body_prefix','top_sig8','top_body_prefix']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(bucket_rows)

    # body-prefix buckets
    prefix_rows = []
    for prefix, rows in prefix_hits.items():
        prefix_rows.append({
            'body_prefix': prefix,
            'hits': len(rows),
            'unique_sig8': len(set(r['sig8'] for r in rows)),
            'top_bucket': Counter(r['bucket'] for r in rows).most_common(1)[0][0],
        })
    prefix_rows.sort(key=lambda r: (-r['hits'], -r['unique_sig8'], r['body_prefix']))

    with (out_dir / 'body_prefix_buckets.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['body_prefix','hits','unique_sig8','top_bucket']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(prefix_rows)

    # exact body sharing across sig8 members
    sharing_rows = []
    for body_md5, sig8s in exact_body_sharing.items():
        if len(sig8s) > 1:
            sharing_rows.append({
                'body_md5': body_md5,
                'sig8_count': len(sig8s),
                'sig8s': ';'.join(sorted(sig8s)),
            })
    sharing_rows.sort(key=lambda r: (-r['sig8_count'], r['body_md5']))

    with (out_dir / 'cross_sig8_exact_body_sharing.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['body_md5','sig8_count','sig8s']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(sharing_rows)

    summary.append(f'total_hits: {len(hit_rows)}')
    summary.append(f'unique_buckets: {len(bucket_rows)}')
    summary.append(f'unique_body_prefix: {len(prefix_rows)}')
    summary.append(f'cross_sig8_exact_body_sharing: {len(sharing_rows)}')
    summary.append('')
    summary.append('Top structural buckets:')
    for row in bucket_rows[:ns.top_buckets]:
        summary.append(
            f'  {row["bucket"]}: hits={row["hits"]} unique_sig8={row["unique_sig8"]} '
            f'unique_body_prefix={row["unique_body_prefix"]} top_sig8={row["top_sig8"]}'
        )
    summary.append('')
    summary.append('Top body-prefix buckets:')
    for row in prefix_rows[:ns.top_buckets]:
        summary.append(
            f'  {row["body_prefix"]}: hits={row["hits"]} unique_sig8={row["unique_sig8"]} '
            f'top_bucket={row["top_bucket"]}'
        )

    # export representatives of top structural buckets
    rep_root = out_dir / 'top_bucket_samples'
    rep_root.mkdir(exist_ok=True)
    rep_rows = []
    for rank, row in enumerate(bucket_rows[:ns.top_buckets], 1):
        bucket = row['bucket']
        bdir = rep_root / f'{rank:02d}'
        bdir.mkdir(parents=True, exist_ok=True)
        sample_rows = bucket_hits[bucket][:3]
        for idx, hit in enumerate(sample_rows, 1):
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
            })

    with (out_dir / 'top_bucket_sample_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket_rank','bucket','sig8','off_hex','body_prefix']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rep_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'sig7': ns.sig7,
        'total_hits': len(hit_rows),
        'unique_buckets': len(bucket_rows),
        'unique_body_prefix': len(prefix_rows),
        'cross_sig8_exact_body_sharing': len(sharing_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
