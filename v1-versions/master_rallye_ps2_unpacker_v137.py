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

def validate_rulepack(rulepack: list[dict[str, Any]]) -> tuple[bool, str]:
    required_keys = {'name', 'sig7', 'prev', 'next', 'members'}
    seen = set()
    for i, rule in enumerate(rulepack):
        missing = required_keys - set(rule.keys())
        if missing:
            return False, f'rule #{i} missing keys: {sorted(missing)}'
        if not isinstance(rule['members'], dict) or not rule['members']:
            return False, f'rule #{i} has empty members'
        if rule['name'] in seen:
            return False, f'duplicate rule name: {rule["name"]}'
        seen.add(rule['name'])
    return True, 'ok'

def normalize_rulepack(rulepack: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rule in rulepack:
        r = dict(rule)
        if 'source' not in r or not r['source']:
            r['source'] = 'manual_base'
        out.append(r)
    return out

def score_bucket_match(hit: dict[str, Any], rule: dict[str, Any]) -> int:
    if not hit['sig8'].startswith(rule['sig7']):
        return 0
    if hit['prev_key'] != rule['prev'] or hit['next_key'] != rule['next']:
        return 0

    expected = rule['members'].get(hit['sig8'])
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

def required_score(rule: dict[str, Any]) -> int:
    member = next(iter(rule['members'].values()))
    return 4 if member.get('tail_sig8') else 3

def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def bucket_slug(bucket: str) -> str:
    return bucket.replace(' || ', '__').replace('@', '_').replace('-', 'm').replace('none', 'n').replace(' ', '')

def branch_key(hit: dict[str, Any]) -> str:
    if hit['next_key'].startswith('0D@'):
        return f"{hit['sig8']} | {hit['body_prefix']} | {hit['tail_sig8']}"
    return f"{hit['sig8']} | {hit['body_prefix']}"

def collect_hits(tng_path: Path, sig7: str, before: int, after: int, body_prefix_bytes: int):
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

            tail = b''
            tail_sig8 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after_buf[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

            hits.append({
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
    return hits

def assign_hits(hits: list[dict[str, Any]], rulepack: list[dict[str, Any]]):
    matched = []
    quarantine = []
    for hit in hits:
        best_rule = None
        best_score = 0
        best_required = 99
        for rule in rulepack:
            score = score_bucket_match(hit, rule)
            req = required_score(rule)
            if score > best_score or (score == best_score and req < best_required):
                best_rule = rule
                best_score = score
                best_required = req

        if best_rule is not None and best_score >= best_required:
            matched.append(hit | {
                'rule_name': best_rule['name'],
                'source': best_rule.get('source', 'unknown'),
                'match_score': best_score,
                'required_score': best_required,
            })
        else:
            quarantine.append(hit | {
                'best_rule_name': best_rule['name'] if best_rule else '',
                'best_score': best_score,
                'required_score': best_required if best_rule else '',
            })
    return matched, quarantine

def main():
    ap = argparse.ArgumentParser(description='BX v137 residual-aware rulepack materializer')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('materialize-rulepack-with-residual')
    p.add_argument('tng_path', type=Path)
    p.add_argument('rulepack_json', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--export-rule-binaries', action='store_true')
    p.add_argument('--export-residual-samples', action='store_true')
    p.add_argument('--top-residual-buckets', type=int, default=40)

    ns = ap.parse_args()
    if ns.cmd != 'materialize-rulepack-with-residual':
        raise SystemExit(1)

    out_dir = Path(ns.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rulepack = json.loads(Path(ns.rulepack_json).read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(rulepack)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')
    rulepack = normalize_rulepack(rulepack)

    hits = collect_hits(
        tng_path=Path(ns.tng_path),
        sig7=ns.sig7,
        before=ns.before,
        after=ns.after,
        body_prefix_bytes=ns.body_prefix_bytes,
    )
    matched, quarantine = assign_hits(hits, rulepack)

    # Materialize matched rules
    rules_root = out_dir / 'rules'
    rules_root.mkdir(exist_ok=True)

    grouped = defaultdict(list)
    for row in matched:
        grouped[row['rule_name']].append(row)

    rule_summary_rows = []
    for rule in rulepack:
        name = rule['name']
        rows = grouped.get(name, [])
        rdir = rules_root / name
        rdir.mkdir(parents=True, exist_ok=True)

        manifest_rows = []
        for i, row in enumerate(rows, 1):
            manifest_rows.append({
                'idx': i,
                'off_hex': row['off_hex'],
                'sig8': row['sig8'],
                'body_md5': row['body_md5'],
                'body_prefix': row['body_prefix'],
                'prev_key': row['prev_key'],
                'next_key': row['next_key'],
                'tail_sig8': row['tail_sig8'],
                'source': row['source'],
                'match_score': row['match_score'],
                'required_score': row['required_score'],
            })
            if ns.export_rule_binaries:
                hdir = rdir / f'{i:03d}_{row["off_hex"]}_{row["sig8"]}'
                hdir.mkdir(parents=True, exist_ok=True)
                (hdir / 'rid0C_507.bin').write_bytes(row['record'])
                if row['tail']:
                    (hdir / 'tail_candidate_54.bin').write_bytes(row['tail'])

        write_csv(
            rdir / 'manifest.csv',
            manifest_rows,
            ['idx', 'off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'source', 'match_score', 'required_score'],
        )
        rule_summary_rows.append({
            'rule_name': name,
            'source': rule.get('source', 'unknown'),
            'hits': len(rows),
            'sig7': rule['sig7'],
            'prev': rule['prev'],
            'next': rule['next'],
        })

    # Materialize residual frontier by bucket
    residual_root = out_dir / 'residual'
    residual_root.mkdir(exist_ok=True)
    residual_bucket_map = defaultdict(list)
    for row in quarantine:
        residual_bucket_map[f'{row["prev_key"]} || {row["next_key"]}'].append(row)

    residual_summary_rows = []
    sorted_buckets = sorted(residual_bucket_map.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for rank, (bucket, rows) in enumerate(sorted_buckets, 1):
        branches = Counter(branch_key(r) for r in rows)
        top_branch, top_count = branches.most_common(1)[0]
        residual_summary_rows.append({
            'rank': rank,
            'bucket': bucket,
            'hits': len(rows),
            'unique_branches': len(branches),
            'top_branch': top_branch,
            'top_count': top_count,
            'dominance': round(top_count / len(rows), 4),
        })

        if rank <= ns.top_residual_buckets:
            bdir = residual_root / f'{rank:02d}_{bucket_slug(bucket)}'
            bdir.mkdir(parents=True, exist_ok=True)
            manifest_rows = []
            for i, row in enumerate(rows, 1):
                manifest_rows.append({
                    'idx': i,
                    'off_hex': row['off_hex'],
                    'sig8': row['sig8'],
                    'body_md5': row['body_md5'],
                    'body_prefix': row['body_prefix'],
                    'prev_key': row['prev_key'],
                    'next_key': row['next_key'],
                    'tail_sig8': row['tail_sig8'],
                    'best_rule_name': row['best_rule_name'],
                    'best_score': row['best_score'],
                    'required_score': row['required_score'],
                    'branch_key': branch_key(row),
                })
                if ns.export_residual_samples and i <= 3:
                    sdir = bdir / f'sample_{i:02d}_{row["off_hex"]}_{row["sig8"]}'
                    sdir.mkdir(parents=True, exist_ok=True)
                    (sdir / 'rid0C_507.bin').write_bytes(row['record'])
                    if row['tail']:
                        (sdir / 'tail_candidate_54.bin').write_bytes(row['tail'])

            write_csv(
                bdir / 'manifest.csv',
                manifest_rows,
                ['idx', 'off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'best_rule_name', 'best_score', 'required_score', 'branch_key'],
            )

    write_csv(
        out_dir / 'rule_summary.csv',
        sorted(rule_summary_rows, key=lambda r: (-r['hits'], r['rule_name'])),
        ['rule_name', 'source', 'hits', 'sig7', 'prev', 'next'],
    )
    write_csv(
        out_dir / 'matched_manifest.csv',
        [
            {
                'rule_name': r['rule_name'],
                'off_hex': r['off_hex'],
                'sig8': r['sig8'],
                'body_md5': r['body_md5'],
                'body_prefix': r['body_prefix'],
                'prev_key': r['prev_key'],
                'next_key': r['next_key'],
                'tail_sig8': r['tail_sig8'],
                'source': r['source'],
            }
            for r in matched
        ],
        ['rule_name', 'off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'source'],
    )
    write_csv(
        out_dir / 'covered_by_source.csv',
        [{'source': k, 'hits': v} for k, v in Counter(r['source'] for r in matched).most_common()],
        ['source', 'hits'],
    )
    write_csv(
        out_dir / 'quarantine' / 'quarantine_manifest.csv',
        [
            {
                'off_hex': r['off_hex'],
                'sig8': r['sig8'],
                'body_md5': r['body_md5'],
                'body_prefix': r['body_prefix'],
                'prev_key': r['prev_key'],
                'next_key': r['next_key'],
                'tail_sig8': r['tail_sig8'],
                'best_rule_name': r['best_rule_name'],
                'best_score': r['best_score'],
                'required_score': r['required_score'],
            }
            for r in quarantine
        ],
        ['off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'best_rule_name', 'best_score', 'required_score'],
    )
    write_csv(
        out_dir / 'quarantine' / 'residual_buckets.csv',
        residual_summary_rows,
        ['rank', 'bucket', 'hits', 'unique_branches', 'top_branch', 'top_count', 'dominance'],
    )

    with (out_dir / 'rulepack_used.json').open('w', encoding='utf-8') as f:
        json.dump(rulepack, f, indent=2)

    summary = []
    summary.append('BX v137 residual-aware rulepack materializer')
    summary.append('===========================================')
    summary.append(f'tng_path: {ns.tng_path}')
    summary.append(f'rulepack_json: {ns.rulepack_json}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'export_rule_binaries: {ns.export_rule_binaries}')
    summary.append(f'export_residual_samples: {ns.export_residual_samples}')
    summary.append(f'total_hits_under_sig7: {len(hits)}')
    summary.append(f'matched_hits: {len(matched)}')
    summary.append(f'quarantine_hits: {len(quarantine)}')
    summary.append(f'coverage_ratio: {len(matched)}/{len(hits)} = {len(matched)/len(hits):.4f}')
    summary.append(f'rulepack_rules: {len(rulepack)}')
    summary.append(f'materialized_residual_buckets: {min(len(residual_summary_rows), ns.top_residual_buckets)}')
    summary.append('')
    summary.append('Covered by source:')
    for k, v in Counter(r['source'] for r in matched).most_common():
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('Top residual buckets:')
    for row in residual_summary_rows[:30]:
        summary.append(
            f'  {row["bucket"]} :: {row["hits"]} | branches={row["unique_branches"]} | top={row["top_branch"]}::{row["top_count"]}'
        )
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

    with (out_dir / 'meta.json').open('w', encoding='utf-8') as f:
        json.dump({
            'total_hits_under_sig7': len(hits),
            'matched_hits': len(matched),
            'quarantine_hits': len(quarantine),
            'coverage_ratio': len(matched) / len(hits),
            'rulepack_rules': len(rulepack),
            'materialized_residual_buckets': min(len(residual_summary_rows), ns.top_residual_buckets),
        }, f, indent=2)

if __name__ == '__main__':
    main()
