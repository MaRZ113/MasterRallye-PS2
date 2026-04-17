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

# Manual clean subclasses after v121
BASE_BUCKET_REGISTRY = [
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
    {
        'name': 'cross_sig8_prevlink_0b295_branch_61_930c',
        'sig7': '0000010c425425',
        'prev': '0B@-295',
        'next': 'none',
        'members': {
            '0000010c42542561': {'body_prefix': '930c'},
        },
    },
    {
        'name': 'cross_sig8_prevlink_0b295_branch_61_f628',
        'sig7': '0000010c425425',
        'prev': '0B@-295',
        'next': 'none',
        'members': {
            '0000010c42542561': {'body_prefix': 'f628'},
        },
    },
    {
        'name': 'cross_sig8_tailed_1188_branch_63_7ea0',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@1188',
        'members': {
            '0000010c42542563': {'body_prefix': '7ea0', 'tail_sig8': '0000010d42486562'},
        },
    },
    {
        'name': 'cross_sig8_tailed_1188_branch_63_7b2e',
        'sig7': '0000010c425425',
        'prev': 'none',
        'next': '0D@1188',
        'members': {
            '0000010c42542563': {'body_prefix': '7b2e', 'tail_sig8': '0000010d424864cb'},
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
    member = next(iter(bucket['members'].values()))
    return 4 if member.get('tail_sig8') else 3

def assign_hits(all_hits, registry):
    framework_rows = []
    quarantine_rows = []

    for hit in all_hits:
        best_bucket = None
        best_score = 0
        best_required = 99

        for bucket in registry:
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
                'source': best_bucket.get('source', 'manual'),
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
    return framework_rows, quarantine_rows

def branch_key(hit):
    if hit['next_key'].startswith('0D@'):
        return f"{hit['sig8']} | {hit['body_prefix']} | {hit['tail_sig8']}"
    return f"{hit['sig8']} | {hit['body_prefix']}"

def propose_name(prev_key: str, next_key: str, sig8: str, body_prefix: str) -> str:
    p = prev_key.replace('@', '_').replace('-', 'm').replace('none', 'n')
    n = next_key.replace('@', '_').replace('-', 'm').replace('none', 'n')
    return f'auto_{p}_{n}_{sig8[-2:]}_{body_prefix}'

def build_auto_rule(sig7: str, prev_key: str, next_key: str, hit: dict, count: int, source: str):
    member = {
        hit['sig8']: {
            'body_prefix': hit['body_prefix'],
            **({'tail_sig8': hit['tail_sig8']} if hit['tail_sig8'] else {})
        }
    }
    return {
        'name': propose_name(prev_key, next_key, hit['sig8'], hit['body_prefix']),
        'sig7': sig7,
        'prev': prev_key,
        'next': next_key,
        'members': member,
        'count': count,
        'source': source,
    }

def bucket_key(bucket):
    return (bucket['prev'], bucket['next'])

def build_pure_quarantine_rules(quarantine_rows, sig7: str, min_count: int, skip_bucket_keys: set[tuple[str,str]]):
    bucket_hits = defaultdict(list)
    for hit in quarantine_rows:
        bucket_hits[(hit['prev_key'], hit['next_key'])].append(hit)

    auto_rules = []
    for (prev_key, next_key), hits in bucket_hits.items():
        if (prev_key, next_key) in skip_bucket_keys:
            continue
        branches = Counter(branch_key(h) for h in hits)
        if len(branches) == 1 and len(hits) >= min_count:
            auto_rules.append(build_auto_rule(sig7, prev_key, next_key, hits[0], len(hits), 'auto_pure_bucket'))
    auto_rules.sort(key=lambda r: (-r['count'], r['name']))
    return auto_rules

def build_backbone_rules(quarantine_rows, sig7: str, min_count: int):
    backbone = [r for r in quarantine_rows if r['prev_key'] == 'none' and r['next_key'] == 'none']
    branch_counts = Counter((r['sig8'], r['body_prefix']) for r in backbone)
    rules = []
    for (sig8, body_prefix), count in branch_counts.items():
        if count >= min_count:
            rules.append({
                'name': f'backbone_none_none_{sig8[-2:]}_{body_prefix}',
                'sig7': sig7,
                'prev': 'none',
                'next': 'none',
                'members': {sig8: {'body_prefix': body_prefix}},
                'count': count,
                'source': 'auto_backbone',
            })
    rules.sort(key=lambda r: (-r['count'], r['name']))
    return rules

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

def main():
    ap = argparse.ArgumentParser(description='BX v126 unified auto-expanding 425425 framework extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-425425-framework-unified')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--min-pure-count', type=int, default=3)
    p.add_argument('--min-backbone-count', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'extract-425425-framework-unified':
        raise SystemExit(1)

    tng_path = Path(ns.tng_path)
    out_dir = Path(ns.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Collect all hits
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

            tail_sig8 = ''
            if next_nearest and next_nearest['rid'] == '0D':
                rel0 = next_nearest['delta'] - RECORD_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

            all_hits.append({
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': md5(body),
                'body_prefix': body_prefix,
                'prev_key': prev_key,
                'next_key': next_key,
                'tail_sig8': tail_sig8,
            })

        mm.close()

    # Wave 1: base manual framework
    base_framework, base_quarantine = assign_hits(all_hits, BASE_BUCKET_REGISTRY)

    # Wave 2: pure quarantine bucket auto-promote outside already-covered bucket keys
    covered_bucket_keys = set(bucket_key(b) for b in BASE_BUCKET_REGISTRY)
    auto_pure_rules = build_pure_quarantine_rules(base_quarantine, ns.sig7, ns.min_pure_count, covered_bucket_keys)
    registry_wave2 = BASE_BUCKET_REGISTRY + auto_pure_rules
    wave2_framework, wave2_quarantine = assign_hits(all_hits, registry_wave2)

    # Wave 3: backbone auto-promote from remaining none||none
    auto_backbone_rules = build_backbone_rules(wave2_quarantine, ns.sig7, ns.min_backbone_count)
    final_registry = registry_wave2 + auto_backbone_rules
    final_framework, final_quarantine = assign_hits(all_hits, final_registry)

    # Outputs
    write_csv(
        out_dir / 'clean_bucket_framework_manifest.csv',
        final_framework,
        ['bucket_name','off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','match_score','required_score','body_prefix_match','tail_sig8_match','source']
    )
    write_csv(
        out_dir / 'quarantine' / 'quarantine_manifest.csv',
        final_quarantine,
        ['off_hex','sig8','body_md5','body_prefix','prev_key','next_key','tail_sig8','best_bucket_name','best_score','required_score']
    )

    with (out_dir / 'auto_pure_rules.json').open('w', encoding='utf-8') as f:
        json.dump(auto_pure_rules, f, indent=2)
    with (out_dir / 'auto_backbone_rules.json').open('w', encoding='utf-8') as f:
        json.dump(auto_backbone_rules, f, indent=2)
    with (out_dir / 'bucket_registry.json').open('w', encoding='utf-8') as f:
        json.dump(final_registry, f, indent=2)

    summary = []
    summary.append('BX v126 unified auto-expanding 425425 framework extractor')
    summary.append('========================================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'base_clean_buckets: {len(BASE_BUCKET_REGISTRY)}')
    summary.append(f'min_pure_count: {ns.min_pure_count}')
    summary.append(f'min_backbone_count: {ns.min_backbone_count}')
    summary.append('')
    summary.append(f'total_hits_under_sig7: {len(all_hits)}')
    summary.append(f'base_assigned_hits: {len(base_framework)}')
    summary.append(f'base_quarantine_hits: {len(base_quarantine)}')
    summary.append(f'auto_pure_rules: {len(auto_pure_rules)}')
    summary.append(f'assigned_hits_after_pure: {len(wave2_framework)}')
    summary.append(f'quarantine_hits_after_pure: {len(wave2_quarantine)}')
    summary.append(f'auto_backbone_rules: {len(auto_backbone_rules)}')
    summary.append(f'assigned_hits_after_backbone: {len(final_framework)}')
    summary.append(f'quarantine_hits_after_backbone: {len(final_quarantine)}')
    summary.append('')

    if auto_pure_rules:
        summary.append('Auto-pure-promoted rules:')
        for rule in auto_pure_rules[:40]:
            sig8, member = next(iter(rule['members'].items()))
            summary.append(
                f'  {rule["name"]}: {rule["prev"]} || {rule["next"]} | '
                f'{sig8} | {member.get("body_prefix","")} | {member.get("tail_sig8","")} :: {rule["count"]}'
            )
        summary.append('')

    if auto_backbone_rules:
        summary.append('Auto-backbone-promoted rules:')
        for rule in auto_backbone_rules[:40]:
            sig8, member = next(iter(rule['members'].items()))
            summary.append(
                f'  {rule["name"]}: {sig8} | {member["body_prefix"]} :: {rule["count"]}'
            )
        summary.append('')

    bucket_counts = Counter(r['bucket_name'] for r in final_framework)
    summary.append('Framework bucket counts:')
    for name, count in bucket_counts.most_common(40):
        summary.append(f'  {name} :: {count}')
    summary.append('')

    q_bucket_counts = Counter(f'{r["prev_key"]} || {r["next_key"]}' for r in final_quarantine)
    summary.append('Top remaining quarantine buckets:')
    for name, count in q_bucket_counts.most_common(40):
        summary.append(f'  {name} :: {count}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'total_hits_under_sig7': len(all_hits),
        'base_assigned_hits': len(base_framework),
        'base_quarantine_hits': len(base_quarantine),
        'auto_pure_rules': len(auto_pure_rules),
        'assigned_hits_after_pure': len(wave2_framework),
        'quarantine_hits_after_pure': len(wave2_quarantine),
        'auto_backbone_rules': len(auto_backbone_rules),
        'assigned_hits_after_backbone': len(final_framework),
        'quarantine_hits_after_backbone': len(final_quarantine),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
