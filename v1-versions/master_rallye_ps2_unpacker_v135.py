#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

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


def score_bucket_match(hit: dict[str, Any], bucket: dict[str, Any]) -> int:
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


def required_score(bucket: dict[str, Any]) -> int:
    member = next(iter(bucket['members'].values()))
    return 4 if member.get('tail_sig8') else 3


def assign_hits(all_hits: list[dict[str, Any]], registry: list[dict[str, Any]]):
    framework = []
    quarantine = []

    for hit in all_hits:
        best_bucket = None
        best_score = 0
        best_required = 99

        for bucket in registry:
            score = score_bucket_match(hit, bucket)
            req = required_score(bucket)
            if score > best_score or (score == best_score and req < best_required):
                best_bucket = bucket
                best_score = score
                best_required = req

        if best_bucket is not None and best_score >= best_required:
            framework.append(hit | {
                'bucket_name': best_bucket['name'],
                'source': best_bucket.get('source', 'unknown'),
                'match_score': best_score,
                'required_score': best_required,
            })
        else:
            quarantine.append(hit | {
                'best_bucket_name': best_bucket['name'] if best_bucket else '',
                'best_score': best_score,
                'required_score': best_required if best_bucket else '',
            })

    return framework, quarantine


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def branch_key(hit: dict[str, Any]) -> str:
    if hit['next_key'].startswith('0D@'):
        return f"{hit['sig8']} | {hit['body_prefix']} | {hit['tail_sig8']}"
    return f"{hit['sig8']} | {hit['body_prefix']}"


def validate_rulepack(rulepack: list[dict[str, Any]]) -> tuple[bool, str]:
    required_bucket_keys = {'name', 'sig7', 'prev', 'next', 'members'}
    seen = set()
    for i, bucket in enumerate(rulepack):
        missing = required_bucket_keys - set(bucket.keys())
        if missing:
            return False, f'rule #{i} missing keys: {sorted(missing)}'
        if not isinstance(bucket['members'], dict) or not bucket['members']:
            return False, f'rule #{i} has empty members'
        if bucket['name'] in seen:
            return False, f'duplicate rule name: {bucket["name"]}'
        seen.add(bucket['name'])
    return True, 'ok'


def collect_sig7_hits(tng_path: Path, sig7: str, before: int, after: int, body_prefix_bytes: int):
    hits = []
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid0c_hits = find_all_mm(mm, RID0C_MARKER)
        for off in rid0c_hits:
            if off + RECORD_LEN > mm.size():
                continue

            rec = bytes(mm[off:off + RECORD_LEN])
            sig8 = rec[:8].hex()
            if not sig8.startswith(sig7):
                continue

            body = rec[8:]
            body_prefix = body[:body_prefix_bytes].hex()

            before_start = max(0, off - before)
            before_buf = bytes(mm[before_start:off])
            after_buf = bytes(mm[off + RECORD_LEN: off + RECORD_LEN + after])

            prev_nearest, next_nearest = nearest_markers(before_buf, after_buf, RECORD_LEN)
            prev_key = f'{prev_nearest["rid"]}@{prev_nearest["delta"]}' if prev_nearest else 'none'
            next_key = f'{next_nearest["rid"]}@{next_nearest["delta"]}' if next_nearest else 'none'

            tail_sig8 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after_buf[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

            hits.append({
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': md5(body),
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'tail_sig8': tail_sig8,
            })
        mm.close()
    return hits


def summarize_residual(quarantine: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bucket_hits = defaultdict(list)
    for hit in quarantine:
        bucket_hits[f'{hit["prev_key"]} || {hit["next_key"]}'].append(hit)

    rows = []
    for bucket, hits in bucket_hits.items():
        branches = Counter(branch_key(h) for h in hits)
        top_branch, top_count = branches.most_common(1)[0]
        rows.append({
            'bucket': bucket,
            'hits': len(hits),
            'unique_branches': len(branches),
            'top_branch': top_branch,
            'top_count': top_count,
            'dominance': round(top_count / len(hits), 4),
        })
    rows.sort(key=lambda r: (-r['hits'], r['unique_branches'], -r['dominance'], r['bucket']))
    return rows


def main():
    ap = argparse.ArgumentParser(description='BX v135 external rulepack extractor for 425425**')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-with-rulepack')
    p.add_argument('tng_path', type=Path)
    p.add_argument('rulepack_json', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)

    ns = ap.parse_args()
    if ns.cmd != 'extract-with-rulepack':
        raise SystemExit(1)

    out_dir = Path(ns.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rulepack = json.loads(Path(ns.rulepack_json).read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(rulepack)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')

    all_hits = collect_sig7_hits(
        tng_path=Path(ns.tng_path),
        sig7=ns.sig7,
        before=ns.before,
        after=ns.after,
        body_prefix_bytes=ns.body_prefix_bytes,
    )

    framework, quarantine = assign_hits(all_hits, rulepack)
    residual_rows = summarize_residual(quarantine)

    write_csv(
        out_dir / 'clean_bucket_framework_manifest.csv',
        framework,
        ['bucket_name', 'off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'source', 'match_score', 'required_score'],
    )
    write_csv(
        out_dir / 'quarantine' / 'quarantine_manifest.csv',
        quarantine,
        ['off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'best_bucket_name', 'best_score', 'required_score'],
    )
    write_csv(
        out_dir / 'residual_frontier.csv',
        residual_rows,
        ['bucket', 'hits', 'unique_branches', 'top_branch', 'top_count', 'dominance'],
    )
    write_csv(
        out_dir / 'covered_by_source.csv',
        [{'source': k, 'hits': v} for k, v in Counter(r['source'] for r in framework).most_common()],
        ['source', 'hits'],
    )
    write_csv(
        out_dir / 'covered_by_bucket.csv',
        [{'bucket_name': k, 'hits': v} for k, v in Counter(r['bucket_name'] for r in framework).most_common()],
        ['bucket_name', 'hits'],
    )

    with (out_dir / 'rulepack_used.json').open('w', encoding='utf-8') as f:
        json.dump(rulepack, f, indent=2)

    summary = []
    summary.append('BX v135 external rulepack extractor')
    summary.append('=================================')
    summary.append(f'tng_path: {ns.tng_path}')
    summary.append(f'rulepack_json: {ns.rulepack_json}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'total_hits_under_sig7: {len(all_hits)}')
    summary.append(f'assigned_hits: {len(framework)}')
    summary.append(f'quarantine_hits: {len(quarantine)}')
    summary.append(f'coverage_ratio: {len(framework)}/{len(all_hits)} = {len(framework)/len(all_hits):.4f}')
    summary.append(f'rulepack_rules: {len(rulepack)}')
    summary.append('')
    summary.append('Covered by source:')
    for k, v in Counter(r['source'] for r in framework).most_common():
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('Top residual frontier buckets:')
    for row in residual_rows[:30]:
        summary.append(f'  {row["bucket"]} :: {row["hits"]} | branches={row["unique_branches"]} | top={row["top_branch"]}::{row["top_count"]}')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

    with (out_dir / 'meta.json').open('w', encoding='utf-8') as f:
        json.dump({
            'total_hits_under_sig7': len(all_hits),
            'assigned_hits': len(framework),
            'quarantine_hits': len(quarantine),
            'coverage_ratio': len(framework) / len(all_hits),
            'rulepack_rules': len(rulepack),
        }, f, indent=2)


if __name__ == '__main__':
    main()
