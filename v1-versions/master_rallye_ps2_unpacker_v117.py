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

# Clean subclasses for 425425**, with promoted stable 0D@552 branches.
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
    {
        'name': 'cross_sig8_tailed_552_branch_61',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@552',
        'members': {
            '0000010c42542561': {'body_prefix': 'cc58', 'tail_sig8': '0000010d424864ce'},
        },
    },
    {
        'name': 'cross_sig8_tailed_552_branch_63',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@552',
        'members': {
            '0000010c42542563': {'body_prefix': '7e61', 'tail_sig8': '0000010d22f03100'},
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

def score_bucket_match(hit, bucket):
    # 0 = none
    # 1 = bucket prev/next only
    # 2 = member sig8
    # 3 = member sig8 + body_prefix
    # 4 = member sig8 + body_prefix + tail_sig8
    if not hit['sig8'].startswith(bucket['sig7']):
        return 0
    if hit['prev_key'] != bucket['prev'] or hit['next_key'] != bucket['next']:
        return 0

    expected = bucket['members'].get(hit['sig8'])
    if not expected:
        return 1

    score = 2
    if expected.get('body_prefix'):
        if hit['body_prefix'] == expected['body_prefix']:
            score = 3
        else:
            return score

    if expected.get('tail_sig8'):
        if hit['tail_sig8'] == expected['tail_sig8']:
            score = 4
        else:
            return score

    return score

def required_score(bucket):
    # Tailed buckets require exact tail_sig8 confirmation.
    member = next(iter(bucket['members'].values()))
    return 4 if member.get('tail_sig8') else 3

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v117 exact-tailed 425425 framework extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-425425-framework-exact')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'extract-425425-framework-exact':
        raise SystemExit(1)

    tng_path = ns.tng_path
    out_dir = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v117 exact-tailed 425425 framework extractor')
    summary.append('===============================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'clean_buckets: {len(BUCKET_REGISTRY)}')
    summary.append('')

    all_hits = []
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
            body_prefix = body[:ns.body_prefix_bytes].hex()

            before_start = max(0, off - ns.before)
            before = bytes(mm[before_start:off])
            after = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + ns.after])

            prev_nearest, next_nearest = nearest_markers(before, after, RECORD_LEN)
            prev_key = f'{prev_nearest["rid"]}@{prev_nearest["delta"]}' if prev_nearest else 'none'
            next_key = f'{next_nearest["rid"]}@{next_nearest["delta"]}' if next_nearest else 'none'

            tail = b''
            tail_sig8 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

            all_hits.append({
                'off': off,
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': md5(body),
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'tail_sig8': tail_sig8,
                'record': rec,
                'tail': tail,
            })

        mm.close()

    framework_rows = []
    quarantine_rows = []

    for hit in all_hits:
        best_bucket = None
        best_score = 0
        best_required = 99

        for bucket in BUCKET_REGISTRY:
            score = score_bucket_match(hit, bucket)
            req = required_score(bucket)
            if score > best_score or (score == best_score and req < best_required):
                best_score = score
                best_required = req
                best_bucket = bucket

        if best_bucket is not None and best_score >= best_required:
            expected = best_bucket['members'][hit['sig8']]
            body_ok = (expected.get('body_prefix', '') == hit['body_prefix']) if expected.get('body_prefix') else True
            tail_ok = (expected.get('tail_sig8', '') == hit['tail_sig8']) if expected.get('tail_sig8') else True
            framework_rows.append({
                'bucket_name': best_bucket['name'],
                'off_hex': hit['off_hex'],
                'sig8': hit['sig8'],
                'body_md5': hit['body_md5'],
                'body_prefix': hit['body_prefix'],
                'prev_key': hit['prev_key'],
                'next_key': hit['next_key'],
                'tail_sig8': hit['tail_sig8'],
                'match_score': best_score,
                'required_score': best_required,
                'body_prefix_match': 1 if body_ok else 0,
                'tail_sig8_match': 1 if tail_ok else 0,
            })
        else:
            quarantine_rows.append({
                'off_hex': hit['off_hex'],
                'sig8': hit['sig8'],
                'body_md5': hit['body_md5'],
                'body_prefix': hit['body_prefix'],
                'prev_key': hit['prev_key'],
                'next_key': hit['next_key'],
                'tail_sig8': hit['tail_sig8'],
                'best_bucket_name': best_bucket['name'] if best_bucket else '',
                'best_score': best_score,
                'required_score': best_required if best_bucket else '',
            })

    bucket_root = out_dir / 'buckets'
    bucket_root.mkdir(exist_ok=True)
    for bucket in BUCKET_REGISTRY:
        bdir = bucket_root / bucket['name']
        bdir.mkdir(parents=True, exist_ok=True)
        rows = [r for r in framework_rows if r['bucket_name'] == bucket['name']]
        with (bdir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
            fieldnames = ['bucket_name','off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','match_score','required_score','body_prefix_match','tail_sig8_match']
            w = csv.DictWriter(f_csv, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

    qdir = out_dir / 'quarantine'
    qdir.mkdir(exist_ok=True)
    with (qdir / 'quarantine_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
        fieldnames = ['off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','best_bucket_name','best_score','required_score']
        w = csv.DictWriter(f_csv, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(quarantine_rows)

    summary.append(f'total_hits_under_sig7: {len(all_hits)}')
    summary.append(f'assigned_hits: {len(framework_rows)}')
    summary.append(f'quarantine_hits: {len(quarantine_rows)}')
    summary.append('')

    for bucket in BUCKET_REGISTRY:
        rows = [r for r in framework_rows if r['bucket_name'] == bucket['name']]
        mismatches = sum(1 for r in rows if not r['body_prefix_match'] or not r['tail_sig8_match'])
        summary.append(f'[{bucket["name"]}] hits={len(rows)} mismatches={mismatches}')
        counts = Counter(r['sig8'] for r in rows)
        for sig8, count in counts.most_common():
            summary.append(f'  {sig8} :: {count}')
        summary.append('')

    q_buckets = Counter(f'{r["prev_key"]} || {r["next_key"]}' for r in quarantine_rows)
    summary.append('Top quarantine buckets:')
    for bucket, count in q_buckets.most_common(12):
        summary.append(f'  {bucket} :: {count}')

    with (out_dir / 'clean_bucket_framework_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
        fieldnames = ['bucket_name','off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','match_score','required_score','body_prefix_match','tail_sig8_match']
        w = csv.DictWriter(f_csv, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(framework_rows)

    (out_dir / 'bucket_registry.json').write_text(json.dumps(BUCKET_REGISTRY, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
