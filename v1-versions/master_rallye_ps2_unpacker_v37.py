#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from itertools import combinations

def common_prefix_len(a: bytes, b: bytes) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i

def main():
    ap = argparse.ArgumentParser(description='BX v37 branch-core extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-branch-cores')
    p.add_argument('v36_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-branch-cores':
        raise SystemExit(1)

    root: Path = ns.v36_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for sig_dir in sorted([p for p in root.iterdir() if p.is_dir() and p.name.startswith('sig_')]):
        samples = []
        metas = []
        for hit_dir in sorted([p for p in sig_dir.iterdir() if p.is_dir() and p.name.startswith('hit_')]):
            fr = hit_dir / 'from_rid01.bin'
            meta = hit_dir / 'meta.json'
            if fr.exists():
                samples.append((hit_dir.name, fr.read_bytes()))
            if meta.exists():
                metas.append(json.loads(meta.read_text(encoding='utf-8')))
        if not samples:
            continue

        # pairwise common prefixes
        cps = []
        for (n1, b1), (n2, b2) in combinations(samples, 2):
            cps.append(common_prefix_len(b1, b2))

        min_cp = min(cps) if cps else len(samples[0][1])
        max_cp = max(cps) if cps else len(samples[0][1])

        sig_out = out_dir / sig_dir.name
        sig_out.mkdir(parents=True, exist_ok=True)

        # shared core = minimum common prefix across samples
        shared_core = samples[0][1][:min_cp]
        (sig_out / 'shared_core.bin').write_bytes(shared_core)
        (sig_out / 'shared_core.hex.txt').write_text(shared_core.hex(), encoding='utf-8')

        # tails per sample
        for name, blob in samples:
            tail = blob[min_cp:]
            (sig_out / f'{name}_tail.bin').write_bytes(tail)
            (sig_out / f'{name}_tail.hex.txt').write_text(tail.hex(), encoding='utf-8')

        meta = {
            'signature_dir': sig_dir.name,
            'sample_count': len(samples),
            'min_common_prefix': min_cp,
            'max_common_prefix': max_cp,
            'rid01_offsets': [m.get('rid01_off') for m in metas],
        }
        (sig_out / 'core_meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        rows.append({
            'signature_dir': sig_dir.name,
            'sample_count': len(samples),
            'min_common_prefix': min_cp,
            'max_common_prefix': max_cp,
        })

    with (out_dir / 'branch_core_summary.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['signature_dir','sample_count','min_common_prefix','max_common_prefix'])
        w.writeheader()
        w.writerows(rows)

    summary = ['BX v37 branch cores','===================']
    for r in rows:
        summary.append(f"{r['signature_dir']}: samples={r['sample_count']} min_cp={r['min_common_prefix']} max_cp={r['max_common_prefix']}")
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
