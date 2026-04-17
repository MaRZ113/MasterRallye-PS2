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


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
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


def cmd_coverage(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rulepack = json.loads(Path(args.rulepack_json).read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(rulepack)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')
    rulepack = normalize_rulepack(rulepack)

    hits = collect_hits(Path(args.tng_path), args.sig7, args.before, args.after, args.body_prefix_bytes)
    matched, quarantine = assign_hits(hits, rulepack)
    residual_rows = summarize_residual(quarantine)

    write_csv(
        out_dir / 'covered_by_source.csv',
        [{'source': k, 'hits': v} for k, v in Counter(r['source'] for r in matched).most_common()],
        ['source', 'hits'],
    )
    write_csv(
        out_dir / 'covered_by_rule.csv',
        [{'rule_name': k, 'hits': v} for k, v in Counter(r['rule_name'] for r in matched).most_common()],
        ['rule_name', 'hits'],
    )
    write_csv(
        out_dir / 'residual_frontier.csv',
        residual_rows,
        ['bucket', 'hits', 'unique_branches', 'top_branch', 'top_count', 'dominance'],
    )

    summary = []
    summary.append('MRPS2 v138 coverage')
    summary.append('===================')
    summary.append(f'total_hits_under_sig7: {len(hits)}')
    summary.append(f'matched_hits: {len(matched)}')
    summary.append(f'quarantine_hits: {len(quarantine)}')
    summary.append(f'coverage_ratio: {len(matched)}/{len(hits)} = {len(matched)/len(hits):.4f}')
    summary.append(f'rulepack_rules: {len(rulepack)}')
    summary.append('')
    summary.append('Top residual buckets:')
    for row in residual_rows[:30]:
        summary.append(f'  {row["bucket"]} :: {row["hits"]} | branches={row["unique_branches"]} | top={row["top_branch"]}::{row["top_count"]}')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')


def cmd_materialize(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rulepack = json.loads(Path(args.rulepack_json).read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(rulepack)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')
    rulepack = normalize_rulepack(rulepack)

    hits = collect_hits(Path(args.tng_path), args.sig7, args.before, args.after, args.body_prefix_bytes)
    matched, quarantine = assign_hits(hits, rulepack)

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
            if args.export_binaries:
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

    with (out_dir / 'rulepack_used.json').open('w', encoding='utf-8') as f:
        json.dump(rulepack, f, indent=2)

    residual = summarize_residual(quarantine)
    summary = []
    summary.append('MRPS2 v138 materialize')
    summary.append('======================')
    summary.append(f'total_hits_under_sig7: {len(hits)}')
    summary.append(f'matched_hits: {len(matched)}')
    summary.append(f'quarantine_hits: {len(quarantine)}')
    summary.append(f'coverage_ratio: {len(matched)}/{len(hits)} = {len(matched)/len(hits):.4f}')
    summary.append(f'rulepack_rules: {len(rulepack)}')
    summary.append('')
    summary.append('Top residual buckets:')
    for row in residual[:30]:
        summary.append(f'  {row["bucket"]} :: {row["hits"]} | branches={row["unique_branches"]} | top={row["top_branch"]}::{row["top_count"]}')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')


def cmd_residualize(args: argparse.Namespace) -> None:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rulepack = json.loads(Path(args.rulepack_json).read_text(encoding='utf-8'))
    ok, msg = validate_rulepack(rulepack)
    if not ok:
        raise SystemExit(f'Invalid rulepack: {msg}')
    rulepack = normalize_rulepack(rulepack)

    hits = collect_hits(Path(args.tng_path), args.sig7, args.before, args.after, args.body_prefix_bytes)
    _, quarantine = assign_hits(hits, rulepack)

    residual_rows = summarize_residual(quarantine)
    residual_root = out_dir / 'residual'
    residual_root.mkdir(exist_ok=True)

    bucket_map = defaultdict(list)
    for row in quarantine:
        bucket_map[f'{row["prev_key"]} || {row["next_key"]}'].append(row)

    for rank, row in enumerate(residual_rows[:args.top_buckets], 1):
        bucket = row['bucket']
        rows = bucket_map[bucket]
        bdir = residual_root / f'{rank:02d}_{bucket_slug(bucket)}'
        bdir.mkdir(parents=True, exist_ok=True)

        manifest_rows = []
        for i, hit in enumerate(rows, 1):
            manifest_rows.append({
                'idx': i,
                'off_hex': hit['off_hex'],
                'sig8': hit['sig8'],
                'body_md5': hit['body_md5'],
                'body_prefix': hit['body_prefix'],
                'prev_key': hit['prev_key'],
                'next_key': hit['next_key'],
                'tail_sig8': hit['tail_sig8'],
                'best_rule_name': hit['best_rule_name'],
                'best_score': hit['best_score'],
                'required_score': hit['required_score'],
                'branch_key': branch_key(hit),
            })
            if args.export_samples and i <= 3:
                sdir = bdir / f'sample_{i:02d}_{hit["off_hex"]}_{hit["sig8"]}'
                sdir.mkdir(parents=True, exist_ok=True)
                (sdir / 'rid0C_507.bin').write_bytes(hit['record'])
                if hit['tail']:
                    (sdir / 'tail_candidate_54.bin').write_bytes(hit['tail'])

        write_csv(
            bdir / 'manifest.csv',
            manifest_rows,
            ['idx', 'off_hex', 'sig8', 'body_md5', 'body_prefix', 'prev_key', 'next_key', 'tail_sig8', 'best_rule_name', 'best_score', 'required_score', 'branch_key'],
        )

    write_csv(
        out_dir / 'residual_buckets.csv',
        residual_rows,
        ['bucket', 'hits', 'unique_branches', 'top_branch', 'top_count', 'dominance'],
    )

    summary = []
    summary.append('MRPS2 v138 residualize')
    summary.append('======================')
    summary.append(f'total_hits_under_sig7: {len(hits)}')
    summary.append(f'quarantine_hits: {len(quarantine)}')
    summary.append(f'materialized_residual_buckets: {min(len(residual_rows), args.top_buckets)}')
    summary.append('')
    summary.append('Top residual buckets:')
    for row in residual_rows[:30]:
        summary.append(f'  {row["bucket"]} :: {row["hits"]} | branches={row["unique_branches"]} | top={row["top_branch"]}::{row["top_count"]}')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description='Master Rallye PS2 TNG.000 rulepack-driven CLI')
    sub = ap.add_subparsers(dest='cmd', required=True)

    def add_common(p):
        p.add_argument('tng_path', type=Path)
        p.add_argument('rulepack_json', type=Path)
        p.add_argument('out_dir', type=Path)
        p.add_argument('--sig7', type=str, default='0000010c425425')
        p.add_argument('--before', type=int, default=512)
        p.add_argument('--after', type=int, default=1400)
        p.add_argument('--body-prefix-bytes', type=int, default=2)

    p_cov = sub.add_parser('coverage', help='Measure rulepack coverage and residual frontier')
    add_common(p_cov)
    p_cov.set_defaults(func=cmd_coverage)

    p_mat = sub.add_parser('materialize', help='Materialize matched hits by rule')
    add_common(p_mat)
    p_mat.add_argument('--export-binaries', action='store_true')
    p_mat.set_defaults(func=cmd_materialize)

    p_res = sub.add_parser('residualize', help='Materialize residual frontier by bucket')
    add_common(p_res)
    p_res.add_argument('--top-buckets', type=int, default=40)
    p_res.add_argument('--export-samples', action='store_true')
    p_res.set_defaults(func=cmd_residualize)

    return ap


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
