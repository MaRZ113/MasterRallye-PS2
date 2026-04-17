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
RID0D_MARKER = b'\x00\x00\x01\x0D'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

# Clean bucket candidates learned from v111
BUCKET_REGISTRY = [
    {
        'name': 'cross_sig8_tailed_508',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@508',
        'members': {
            '0000010c42542562': {'body_prefix': 'bc82', 'tail_sig8': '0000010d424864cb'},
            '0000010c42542563': {'body_prefix': '7e79', 'tail_sig8': '0000010d424864c3'},
        },
    },
    {
        'name': 'cross_sig8_prevlink_0b313',
        'sig7': '0000010c425425',
        'prev': '0B@-313',
        'next': 'none',
        'members': {
            '0000010c42542561': {'body_prefix': 'a618'},
            '0000010c42542562': {'body_prefix': 'b65d'},
        },
    },
    {
        'name': 'cross_sig8_tailed_832_asymmetric',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@832',
        'members': {
            '0000010c42542562': {'body_prefix': 'bf6a', 'tail_sig8': '0000010d424864cb'},
            '0000010c42542563': {'body_prefix': 'b141', 'tail_sig8': '0000010d424864c3'},
        },
    },
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

def main():
    ap = argparse.ArgumentParser(description='BX v112 clean bucket registry extractor for 425425**')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-clean-buckets')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'extract-clean-buckets':
        raise SystemExit(1)

    tng_path = ns.tng_path
    out_dir = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v112 clean bucket registry extractor')
    summary.append('======================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'buckets: {len(BUCKET_REGISTRY)}')
    summary.append('')

    manifest_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all_mm(mm, RID0C_MARKER)

        for bucket in BUCKET_REGISTRY:
            bdir = out_dir / bucket['name']
            bdir.mkdir(parents=True, exist_ok=True)

            bucket_rows = []
            mismatch_count = 0

            for off in hits:
                if off + RECORD_LEN > mm.size():
                    continue
                rec = bytes(mm[off:off + RECORD_LEN])
                sig8 = rec[:8].hex()
                if not sig8.startswith(bucket['sig7']):
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

                if prev_key != bucket['prev'] or next_key != bucket['next']:
                    continue

                rel0 = None
                tail_sig8 = ''
                if next_nearest and next_nearest['rid'] == '0D':
                    rel0 = next_nearest['delta'] - RECORD_LEN
                    tail = after[rel0:rel0 + TAIL_LEN]
                    tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''
                else:
                    tail = b''

                expected = bucket['members'].get(sig8, {})
                expected_body_prefix = expected.get('body_prefix', '')
                expected_tail_sig8 = expected.get('tail_sig8', '')

                body_prefix_match = (not expected_body_prefix) or (body_prefix == expected_body_prefix)
                tail_sig8_match = (not expected_tail_sig8) or (tail_sig8 == expected_tail_sig8)
                if not body_prefix_match or not tail_sig8_match:
                    mismatch_count += 1

                hdir = bdir / f'{sig8}_{off:08X}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'rid0C_507.bin', rec)
                if tail:
                    write_bytes(hdir / 'tail_candidate_54.bin', tail)

                row = {
                    'bucket_name': bucket['name'],
                    'off_hex': f'0x{off:X}',
                    'sig8': sig8,
                    'body_md5': body_md5,
                    'body_prefix': body_prefix,
                    'tail_sig8': tail_sig8,
                    'body_prefix_match': 1 if body_prefix_match else 0,
                    'tail_sig8_match': 1 if tail_sig8_match else 0,
                }
                (hdir / 'meta.json').write_text(json.dumps(row, indent=2), encoding='utf-8')

                bucket_rows.append(row)
                manifest_rows.append(row)

            with (bdir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
                fieldnames = ['bucket_name','off_hex','sig8','body_md5','body_prefix','tail_sig8','body_prefix_match','tail_sig8_match']
                w = csv.DictWriter(f_csv, fieldnames=fieldnames)
                w.writeheader()
                w.writerows(bucket_rows)

            sig8_counts = Counter(r['sig8'] for r in bucket_rows)
            summary.append(
                f'[{bucket["name"]}] hits={len(bucket_rows)} unique_sig8={len(sig8_counts)} mismatches={mismatch_count}'
            )
            for sig8, count in sig8_counts.most_common():
                summary.append(f'  {sig8} :: {count}')
            summary.append('')

        mm.close()

    with (out_dir / 'clean_bucket_framework_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
        fieldnames = ['bucket_name','off_hex','sig8','body_md5','body_prefix','tail_sig8','body_prefix_match','tail_sig8_match']
        w = csv.DictWriter(f_csv, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'bucket_registry.json').write_text(json.dumps(BUCKET_REGISTRY, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
