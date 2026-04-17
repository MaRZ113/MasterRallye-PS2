#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
import json
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def find_family_dirs(v74_root: Path):
    fam_root = v74_root / 'sig8_families'
    if not fam_root.exists():
        raise FileNotFoundError(f'No sig8_families in {v74_root}')
    return sorted([p for p in fam_root.iterdir() if p.is_dir()])

def first_sample_bin(fam_dir: Path):
    samples = sorted(fam_dir.glob('sample_*.bin'))
    return samples[0] if samples else None

def longest_match(a: bytes, b: bytes):
    sm = difflib.SequenceMatcher(a=list(a), b=list(b), autojunk=False)
    blk = sm.find_longest_match(0, len(a), 0, len(b))
    return blk.a, blk.b, blk.size

def common_prefix_len(a: bytes, b: bytes):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i

def common_suffix_len(a: bytes, b: bytes):
    n = min(len(a), len(b))
    i = 0
    while i < n and a[-1-i] == b[-1-i]:
        i += 1
    return i

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v82 rid0C cousin core-of-cores miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-cousin-core')
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--top-n', type=int, default=12)
    p.add_argument('--min-match', type=int, default=96)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-cousin-core':
        raise SystemExit(1)

    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_dirs = find_family_dirs(v74_root)[:ns.top_n]
    items = []
    for fam_dir in fam_dirs:
        sample = first_sample_bin(fam_dir)
        if not sample:
            continue
        blob = read_bytes(sample)
        items.append({
            'family_dir': fam_dir.name,
            'sig8': fam_dir.name.split('_', 1)[1] if '_' in fam_dir.name else fam_dir.name,
            'sample_name': sample.name,
            'data': blob,
        })

    summary = []
    summary.append('BX v82 rid0C cousin core-of-cores')
    summary.append('=================================')
    summary.append(f'v74_root: {v74_root}')
    summary.append(f'families_loaded: {len(items)}')
    summary.append(f'min_match: {ns.min_match}')
    summary.append('')

    rows = []
    kept_pairs = []
    for i in range(len(items)):
        for j in range(i+1, len(items)):
            a = items[i]
            b = items[j]
            cp = common_prefix_len(a['data'], b['data'])
            cs = common_suffix_len(a['data'], b['data'])
            ma, mb, ms = longest_match(a['data'], b['data'])
            rows.append({
                'a_family': a['family_dir'],
                'b_family': b['family_dir'],
                'a_sig8': a['sig8'],
                'b_sig8': b['sig8'],
                'common_prefix': cp,
                'common_suffix': cs,
                'longest_match_a': ma,
                'longest_match_b': mb,
                'longest_match_len': ms,
                'delta_b_minus_a': mb - ma,
            })
            if ms >= ns.min_match:
                kept_pairs.append((a, b, ma, mb, ms, mb - ma))

    with (out_dir / 'pairwise_longest_matches.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['a_family','b_family','a_sig8','b_sig8','common_prefix','common_suffix','longest_match_a','longest_match_b','longest_match_len','delta_b_minus_a']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (-r['longest_match_len'], -r['common_prefix'], r['a_sig8'], r['b_sig8'])))

    # export big shared blocks
    match_root = out_dir / 'big_matches'
    match_root.mkdir(exist_ok=True)
    rep_rows = []
    for idx, (a, b, ma, mb, ms, delta) in enumerate(sorted(kept_pairs, key=lambda x: -x[4]), 1):
        seg = a['data'][ma:ma+ms]
        mdir = match_root / f'{idx:02d}_{a["sig8"]}__{b["sig8"]}'
        mdir.mkdir(parents=True, exist_ok=True)
        write_bytes(mdir / 'shared_block.bin', seg)
        (mdir / 'shared_block.hex.txt').write_text(seg.hex(), encoding='utf-8')
        rep_rows.append({
            'rank': idx,
            'a_sig8': a['sig8'],
            'b_sig8': b['sig8'],
            'a_family': a['family_dir'],
            'b_family': b['family_dir'],
            'a_off': ma,
            'b_off': mb,
            'len': ms,
            'delta_b_minus_a': delta,
            'head16': seg[:16].hex(),
        })
        summary.append(
            f'{idx:02d}) {a["sig8"]} vs {b["sig8"]}: len={ms} a@{ma} b@{mb} delta={delta} head16={seg[:16].hex()}'
        )

    with (out_dir / 'big_match_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['rank','a_sig8','b_sig8','a_family','b_family','a_off','b_off','len','delta_b_minus_a','head16']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rep_rows)

    meta = {
        'families_loaded': len(items),
        'pairs_total': len(rows),
        'pairs_with_big_match': len(rep_rows),
        'min_match': ns.min_match,
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
