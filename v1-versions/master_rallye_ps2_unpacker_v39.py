#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def common_prefix_len(a: bytes, b: bytes) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i

def longest_common_prefix(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    pref = blobs[0]
    for b in blobs[1:]:
        l = common_prefix_len(pref, b)
        pref = pref[:l]
        if not pref:
            break
    return len(pref)

def main():
    ap = argparse.ArgumentParser(description='BX v39 branch-aware packet extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-branch-packets')
    p.add_argument('v38_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'extract-branch-packets':
        raise SystemExit(1)

    root: Path = ns.v38_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Discover reconstructed samples
    branches = [
        ('BXI_', root / 'branch_BXI_'),
        ('BXI1', root / 'branch_BXI1'),
    ]

    manifest = []
    summary = []
    summary.append('BX v39 branch-aware packet extractor')
    summary.append('==================================')
    summary.append(f'v38_root: {root}')
    summary.append('')

    for branch_name, bdir in branches:
        samples = sorted(bdir.glob('*_reconstructed.bin'))
        blobs = [read_bytes(p) for p in samples]
        lcp = longest_common_prefix(blobs)

        out_branch = out_dir / f'branch_{branch_name}'
        out_branch.mkdir(parents=True, exist_ok=True)

        # shared template
        shared = blobs[0][:lcp] if blobs else b''
        (out_branch / 'shared_template.bin').write_bytes(shared)
        (out_branch / 'shared_template.hex.txt').write_text(shared.hex(), encoding='utf-8')

        summary.append(f'{branch_name}: samples={len(samples)} shared_template_len={lcp}')

        for sp, blob in zip(samples, blobs):
            sample_name = sp.stem.replace('_reconstructed', '')
            tail = blob[lcp:]
            sdir = out_branch / sample_name
            sdir.mkdir(parents=True, exist_ok=True)

            (sdir / 'packet.bin').write_bytes(blob)
            (sdir / 'packet.hex.txt').write_text(blob.hex(), encoding='utf-8')
            (sdir / 'tail.bin').write_bytes(tail)
            (sdir / 'tail.hex.txt').write_text(tail.hex(), encoding='utf-8')

            manifest.append({
                'branch': branch_name,
                'sample': sample_name,
                'packet_len': len(blob),
                'shared_template_len': lcp,
                'tail_len': len(tail),
            })

        # pairwise common-prefix matrix
        matrix_rows = []
        for i, (spa, ba) in enumerate(zip(samples, blobs)):
            for j, (spb, bb) in enumerate(zip(samples, blobs)):
                if j <= i:
                    continue
                matrix_rows.append({
                    'sample_a': spa.stem.replace('_reconstructed', ''),
                    'sample_b': spb.stem.replace('_reconstructed', ''),
                    'common_prefix_len': common_prefix_len(ba, bb),
                })
        with (out_branch / 'pairwise_prefix.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['sample_a','sample_b','common_prefix_len'])
            w.writeheader()
            w.writerows(matrix_rows)

    with (out_dir / 'branch_packet_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['branch','sample','packet_len','shared_template_len','tail_len'])
        w.writeheader()
        w.writerows(manifest)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
