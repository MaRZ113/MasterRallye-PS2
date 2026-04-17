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

# Current clean subclasses after v121
CLEAN_BUCKETS = [
    ('none', '0D@508'),
    ('0B@-313', 'none'),
    ('none', '0D@832'),
    ('none', '0D@552'),
    ('0B@-295', 'none'),
    ('none', '0D@1188'),
]

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

def branch_key(hit):
    if hit['next_key'].startswith('0D@'):
        return f"{hit['sig8']} | {hit['body_prefix']} | {hit['tail_sig8']}"
    return f"{hit['sig8']} | {hit['body_prefix']}"

def main():
    ap = argparse.ArgumentParser(description='BX v122 pure quarantine bucket miner for 425425**')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-pure-quarantine-buckets')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--min-count', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'mine-pure-quarantine-buckets':
        raise SystemExit(1)

    tng_path = ns.tng_path
    out_dir = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    clean_bucket_set = set(CLEAN_BUCKETS)

    summary = []
    summary.append('BX v122 pure quarantine bucket miner')
    summary.append('===================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'min_count: {ns.min_count}')
    summary.append('')

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

            # skip already clean bucket families
            if (prev_key, next_key) in clean_bucket_set:
                continue

            tail_sig8 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''
            else:
                tail = b''

            hit = {
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': body_md5,
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'tail_sig8': tail_sig8,
                'record': rec,
                'tail': tail,
            }
            bucket_hits[f'{prev_key} || {next_key}'].append(hit)

        mm.close()

    pure_rows = []
    noisy_rows = []
    export_root = out_dir / 'pure_bucket_samples'
    export_root.mkdir(exist_ok=True)

    for bucket, hits in sorted(bucket_hits.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        branch_counts = Counter(branch_key(h) for h in hits)
        top_branch, top_count = branch_counts.most_common(1)[0]
        pure = (len(branch_counts) == 1 and len(hits) >= ns.min_count)

        row = {
            'bucket': bucket,
            'hits': len(hits),
            'unique_branches': len(branch_counts),
            'top_branch': top_branch,
            'top_count': top_count,
            'status': 'pure' if pure else 'mixed',
        }

        if pure:
            sample_dir = export_root / bucket.replace('|', '_').replace('@', '_').replace(' ', '')
            sample_dir.mkdir(parents=True, exist_ok=True)
            for idx, hit in enumerate(hits[:3], 1):
                write_bytes(sample_dir / f'sample_{idx:02d}_{hit["sig8"]}_{hit["off_hex"]}.bin', hit['record'])
                if hit['tail']:
                    write_bytes(sample_dir / f'sample_{idx:02d}_{hit["sig8"]}_{hit["off_hex"]}_tail.bin', hit['tail'])

            sig8 = hits[0]['sig8']
            body_prefix = hits[0]['body_prefix']
            tail_sig8 = hits[0]['tail_sig8']
            proposed = {
                'name': f'auto_{bucket.replace(" || ", "_").replace("@","_").replace("-","m").replace("none","n")}_{sig8[-2:]}_{body_prefix}',
                'sig7': ns.sig7,
                'prev': hits[0]['prev_key'],
                'next': hits[0]['next_key'],
                'member': {
                    sig8: {
                        'body_prefix': body_prefix,
                        **({'tail_sig8': tail_sig8} if tail_sig8 else {})
                    }
                },
                'count': len(hits),
            }
            row['proposed_rule'] = json.dumps(proposed, ensure_ascii=False)
            pure_rows.append(row)
        else:
            noisy_rows.append(row)

    with (out_dir / 'pure_bucket_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket','hits','unique_branches','top_branch','top_count','status','proposed_rule']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in pure_rows:
            w.writerow(row)

    with (out_dir / 'mixed_bucket_candidates.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['bucket','hits','unique_branches','top_branch','top_count','status']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in noisy_rows:
            w.writerow(row)

    proposed_rules = [json.loads(r['proposed_rule']) for r in pure_rows]
    (out_dir / 'proposed_rules.json').write_text(json.dumps(proposed_rules, indent=2), encoding='utf-8')

    summary.append(f'quarantine_buckets_scanned: {len(bucket_hits)}')
    summary.append(f'pure_bucket_candidates: {len(pure_rows)}')
    summary.append(f'mixed_bucket_candidates: {len(noisy_rows)}')
    summary.append('')
    summary.append('Pure bucket candidates:')
    for row in pure_rows[:20]:
        summary.append(f'  {row["bucket"]}: hits={row["hits"]} top_branch={row["top_branch"]}')
    summary.append('')
    summary.append('Top mixed bucket candidates:')
    for row in noisy_rows[:20]:
        summary.append(f'  {row["bucket"]}: hits={row["hits"]} branches={row["unique_branches"]} top_branch={row["top_branch"]}::{row["top_count"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'quarantine_buckets_scanned': len(bucket_hits),
        'pure_bucket_candidates': len(pure_rows),
        'mixed_bucket_candidates': len(noisy_rows),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
