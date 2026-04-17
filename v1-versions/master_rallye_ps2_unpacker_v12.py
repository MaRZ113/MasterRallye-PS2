#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, hashlib, statistics
from pathlib import Path
from collections import defaultdict, Counter
import math


def load_manifest(profile_dir: Path):
    path = profile_dir / 'manifest.csv'
    rows = []
    with path.open('r', encoding='utf-8', newline='') as f:
        r = csv.DictReader(f)
        for row in r:
            row['chain_index'] = int(row['chain_index'])
            row['rid'] = int(row['rid'])
            row['start'] = int(row['start'])
            row['payload_start'] = int(row['payload_start']) if row['payload_start'] else None
            row['payload_len'] = int(float(row['payload_len'])) if row['payload_len'] else None
            rows.append(row)
    return rows


def group_by_rid(rows):
    d = defaultdict(list)
    for row in rows:
        d[row['rid']].append(row)
    return d


def median_or_none(vals):
    vals = [v for v in vals if v is not None]
    return None if not vals else int(statistics.median(vals))


def summarize_rid(rows):
    payloads = [r['payload_len'] for r in rows if r['payload_len'] is not None]
    tags = Counter(r['tag_ascii'] for r in rows)
    md5s = Counter(r['md5'] for r in rows if r.get('md5'))
    return {
        'count': len(rows),
        'payload_min': min(payloads) if payloads else None,
        'payload_med': median_or_none(payloads),
        'payload_max': max(payloads) if payloads else None,
        'unique_md5': len(md5s),
        'unique_tags': len(tags),
        'tags': dict(tags),
    }


def classify_rid(rid: int) -> str:
    if 1 <= rid <= 4:
        return 'header'
    if 5 <= rid <= 7:
        return 'descriptor'
    if 8 <= rid <= 15:
        return 'data'
    if rid == 16:
        return 'terminal'
    return 'unknown'


def compare_profiles(full_dir: Path, variant_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    full = load_manifest(full_dir)
    variant = load_manifest(variant_dir)
    fg = group_by_rid(full)
    vg = group_by_rid(variant)
    rows = []
    for rid in sorted(set(fg) | set(vg)):
        fs = summarize_rid(fg.get(rid, [])) if rid in fg else None
        vs = summarize_rid(vg.get(rid, [])) if rid in vg else None
        rows.append({
            'rid': rid,
            'role': classify_rid(rid),
            'full_count': fs['count'] if fs else 0,
            'variant_count': vs['count'] if vs else 0,
            'full_payload_med': fs['payload_med'] if fs else None,
            'variant_payload_med': vs['payload_med'] if vs else None,
            'full_unique_md5': fs['unique_md5'] if fs else 0,
            'variant_unique_md5': vs['unique_md5'] if vs else 0,
            'full_unique_tags': fs['unique_tags'] if fs else 0,
            'variant_unique_tags': vs['unique_tags'] if vs else 0,
            'full_tags': json.dumps(fs['tags'], ensure_ascii=False) if fs else '{}',
            'variant_tags': json.dumps(vs['tags'], ensure_ascii=False) if vs else '{}',
        })
    csv_path = out_dir / 'rid_compare.csv'
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    lines = []
    lines.append('BX v12 rid-level compare')
    lines.append('=======================')
    lines.append(f'full_profile: {full_dir}')
    lines.append(f'variant_profile: {variant_dir}')
    lines.append('')
    lines.append('Key interpretation:')
    lines.append('- rid 01-04: header/control')
    lines.append('- rid 05-07: descriptor/family-specific')
    lines.append('- rid 08-15: payload-bearing')
    lines.append('- rid 16: terminal')
    lines.append('')
    for row in rows:
        lines.append(
            f"rid {row['rid']:02d} [{row['role']}]: full_med={row['full_payload_med']} variant_med={row['variant_payload_med']} "
            f"full_md5={row['full_unique_md5']} variant_md5={row['variant_unique_md5']}"
        )
    # shortlist
    lines.append('')
    lines.append('Suggested next reverse focus:')
    lines.append('1) rid 01-04 as framed header records')
    lines.append('2) rid 05-07 as family descriptors')
    lines.append('3) rid 08-15 as data/payload records')
    lines.append('4) start with rid 05, 08, 09, 10, 12, 13, 14, 15')
    txt_path = out_dir / 'rid_compare.txt'
    txt_path.write_text('\n'.join(lines), encoding='utf-8')
    return txt_path, csv_path


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('compare-rids')
    p.add_argument('full_profile', type=Path)
    p.add_argument('variant_profile', type=Path)
    p.add_argument('out_dir', type=Path)
    args = ap.parse_args()
    if args.cmd == 'compare-rids':
        txt, csvp = compare_profiles(args.full_profile, args.variant_profile, args.out_dir)
        print(f'wrote {txt}')
        print(f'wrote {csvp}')

if __name__ == '__main__':
    main()
