#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import List, Dict

TOP_SUBBRANCHES = ['0000010a43fc', '0000010a423f']

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def load_rep_rows(v55_root: Path) -> List[Dict]:
    path = v55_root / 'representative_binary_families.csv'
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def load_record(v55_root: Path, family_rank: str, sig5: str, index: str, off_hex: str) -> bytes:
    fam_dir = v55_root / 'representatives' / f'fam_{int(family_rank):02d}_{sig5}'
    hit_dir = fam_dir / f'hit_{int(index):05d}_{off_hex}'
    return read_bytes(hit_dir / 'rid0A_record_253.bin')

def main():
    ap = argparse.ArgumentParser(description='BX v57 rid0A subbranch template builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-rid0a-subbranches')
    p.add_argument('v55_root', type=Path)
    p.add_argument('strong_counts_csv', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--max-strong-per-subbranch', type=int, default=12)

    ns = ap.parse_args()
    if ns.cmd != 'build-rid0a-subbranches':
        raise SystemExit(1)

    v55_root: Path = ns.v55_root
    strong_csv: Path = ns.strong_counts_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rep_rows = load_rep_rows(v55_root)
    with strong_csv.open('r', encoding='utf-8', newline='') as f:
        strong_rows = list(csv.DictReader(f))

    # aggregate top strong sig8 under target subbranches
    strong_by_sub = defaultdict(list)
    for r in strong_rows:
        sig8 = r['sig8']
        count = int(r['count'])
        for subhex in TOP_SUBBRANCHES:
            if sig8.startswith(subhex):
                strong_by_sub[subhex].append({'sig8': sig8, 'count': count})

    summary = []
    summary.append('BX v57 rid0A subbranch templates')
    summary.append('================================')
    summary.append(f'v55_root: {v55_root}')
    summary.append(f'strong_counts_csv: {strong_csv}')
    summary.append('')

    sub_meta_rows = []

    # representative records available in v55 are only a sample set, but enough to build first templates
    for subhex in TOP_SUBBRANCHES:
        sdir = out_dir / f'sub_{subhex}'
        sdir.mkdir(parents=True, exist_ok=True)

        # select representative rows whose sig8 starts with subhex
        reps = [r for r in rep_rows if r['sig8'].startswith(subhex)]
        blobs = []
        sample_rows = []

        for r in reps:
            data = load_record(v55_root, r['family_rank'], r['sig5'], r['index'], r['off_hex'])
            blobs.append(data)
            sample_rows.append({
                'family_rank': r['family_rank'],
                'sig5': r['sig5'],
                'sig8': r['sig8'],
                'index': r['index'],
                'off_hex': r['off_hex'],
                'entropy': r['entropy'],
                'printable_ratio': r['printable_ratio'],
                'len': len(data),
            })
            hit_name = f'hit_{int(r["index"]):05d}_{r["off_hex"]}'
            write_bytes(sdir / f'{hit_name}.bin', data)
            (sdir / f'{hit_name}.hex.txt').write_text(data.hex(), encoding='utf-8')

        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)

        if blobs:
            shared_head = blobs[0][:cp]
            shared_tail = blobs[0][len(blobs[0])-cs:] if cs > 0 else b''
            write_bytes(sdir / 'shared_head.bin', shared_head)
            (sdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
            if cs > 0:
                write_bytes(sdir / 'shared_tail.bin', shared_tail)
                (sdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

            # bodies
            for r, data in zip(sample_rows, blobs):
                body = data[cp: len(data)-cs if cs > 0 else len(data)]
                hit_name = f'hit_{int(r["index"]):05d}_{r["off_hex"]}'
                write_bytes(sdir / f'{hit_name}_body.bin', body)
                (sdir / f'{hit_name}_body.hex.txt').write_text(body.hex(), encoding='utf-8')
                r['shared_head_len'] = cp
                r['shared_tail_len'] = cs
                r['body_len'] = len(body)

        with (sdir / 'representative_manifest.csv').open('w', encoding='utf-8', newline='') as f:
            fieldnames = ['family_rank','sig5','sig8','index','off_hex','entropy','printable_ratio','len','shared_head_len','shared_tail_len','body_len']
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(sample_rows)

        # write list of top strong sig8 families under this subbranch
        strong_top = sorted(strong_by_sub[subhex], key=lambda x: (-x['count'], x['sig8']))[:ns.max_strong_per_subbranch]
        with (sdir / 'top_strong_sig8.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['sig8','count'])
            w.writeheader()
            w.writerows(strong_top)

        total_est = sum(x['count'] for x in strong_by_sub[subhex])
        summary.append(f'{subhex}: strong_sig8_groups={len(strong_by_sub[subhex])} approx_hits={total_est} reps={len(sample_rows)} shared_head={cp} shared_tail={cs}')
        if strong_top:
            summary.append('  top sig8:')
            for row in strong_top[:8]:
                summary.append(f'    {row["sig8"]}: {row["count"]}')
        summary.append('')

        sub_meta_rows.append({
            'subbranch': subhex,
            'strong_sig8_groups': len(strong_by_sub[subhex]),
            'approx_hits': total_est,
            'representatives': len(sample_rows),
            'shared_head_len': cp,
            'shared_tail_len': cs,
        })

    with (out_dir / 'subbranch_meta.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['subbranch','strong_sig8_groups','approx_hits','representatives','shared_head_len','shared_tail_len'])
        w.writeheader()
        w.writerows(sub_meta_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
