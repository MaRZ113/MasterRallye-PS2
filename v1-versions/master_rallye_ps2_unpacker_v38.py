#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

def common_prefix_len(a: bytes, b: bytes) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def read_bytes(path: Path) -> bytes:
    return path.read_bytes()

def main():
    ap = argparse.ArgumentParser(description='BX v38 branch supercore reconstructor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-supercore')
    p.add_argument('v37_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-supercore':
        raise SystemExit(1)

    root: Path = ns.v37_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    sig_bxi = root / 'sig_BX_H__BX91__BXA0__BXI_'
    sig_bxi1 = root / 'sig_BX_H__BX91__BXA0__BXI1'

    core_bxi = read_bytes(sig_bxi / 'shared_core.bin')
    core_bxi1 = read_bytes(sig_bxi1 / 'shared_core.bin')

    supercore_len = common_prefix_len(core_bxi, core_bxi1)
    supercore = core_bxi[:supercore_len]
    bxi_suffix = core_bxi[supercore_len:]
    bxi1_suffix = core_bxi1[supercore_len:]

    write_bytes(out_dir / 'supercore.bin', supercore)
    write_bytes(out_dir / 'branch_suffix_BXI_.bin', bxi_suffix)
    write_bytes(out_dir / 'branch_suffix_BXI1.bin', bxi1_suffix)

    (out_dir / 'supercore.hex.txt').write_text(supercore.hex(), encoding='utf-8')
    (out_dir / 'branch_suffix_BXI_.hex.txt').write_text(bxi_suffix.hex(), encoding='utf-8')
    (out_dir / 'branch_suffix_BXI1.hex.txt').write_text(bxi1_suffix.hex(), encoding='utf-8')

    summary = []
    summary.append('BX v38 branch supercore')
    summary.append('=======================')
    summary.append(f'core_BXI_len: {len(core_bxi)}')
    summary.append(f'core_BXI1_len: {len(core_bxi1)}')
    summary.append(f'supercore_len: {supercore_len}')
    summary.append(f'BXI_suffix_len: {len(bxi_suffix)}')
    summary.append(f'BXI1_suffix_len: {len(bxi1_suffix)}')
    summary.append('')

    manifest_rows = []

    # Rebuild branch packets from supercore + suffix + tail
    for sig_name, sig_dir, suffix_name, suffix_bytes in [
        ('BXI_', sig_bxi, 'branch_suffix_BXI_.bin', bxi_suffix),
        ('BXI1', sig_bxi1, 'branch_suffix_BXI1.bin', bxi1_suffix),
    ]:
        tails = sorted(sig_dir.glob('*_tail.bin'))
        branch_out = out_dir / f'branch_{sig_name}'
        branch_out.mkdir(parents=True, exist_ok=True)

        for tail_path in tails:
            tail = read_bytes(tail_path)
            recon = supercore + suffix_bytes + tail
            base = tail_path.stem.replace('_tail', '')

            write_bytes(branch_out / f'{base}_tail.bin', tail)
            write_bytes(branch_out / f'{base}_reconstructed.bin', recon)
            (branch_out / f'{base}_reconstructed.hex.txt').write_text(recon.hex(), encoding='utf-8')

            manifest_rows.append({
                'branch': sig_name,
                'sample': base,
                'tail_len': len(tail),
                'reconstructed_len': len(recon),
                'supercore_len': len(supercore),
                'branch_suffix_len': len(suffix_bytes),
            })

            summary.append(
                f'{sig_name} {base}: tail={len(tail)} reconstructed={len(recon)}'
            )

    with (out_dir / 'reconstruction_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['branch','sample','tail_len','reconstructed_len','supercore_len','branch_suffix_len'])
        w.writeheader()
        w.writerows(manifest_rows)

    meta = {
        'supercore_len': len(supercore),
        'BXI_core_len': len(core_bxi),
        'BXI1_core_len': len(core_bxi1),
        'BXI_suffix_len': len(bxi_suffix),
        'BXI1_suffix_len': len(bxi1_suffix),
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
