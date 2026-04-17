#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

RID0D = b'\x00\x00\x01\x0D'

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

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

def main():
    ap = argparse.ArgumentParser(description='BX v88 rid0C flexible 0D alignment mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-flex-0d')
    p.add_argument('v86_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--tail-len', type=int, default=54)

    ns = ap.parse_args()
    if ns.cmd != 'map-flex-0d':
        raise SystemExit(1)

    v86_root: Path = ns.v86_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    summary = []
    summary.append('BX v88 rid0C flexible 0D alignment')
    summary.append('==================================')
    summary.append(f'v86_root: {v86_root}')
    summary.append('')

    for form in ['standalone', 'tailed']:
        form_dir = v86_root / form
        if not form_dir.exists():
            continue

        sample_dirs = sorted([p for p in form_dir.iterdir() if p.is_dir()])
        summary.append(f'[{form}] samples={len(sample_dirs)}')

        for sdir in sample_dirs:
            gap = read_bytes(sdir / 'gap_314.bin')
            tail = read_bytes(sdir / 'tail_candidate_54.bin')
            post = read_bytes(sdir / 'post_tail.bin')
            zone = gap + tail + post

            offs = find_all(zone, RID0D)
            hit_dir = out_dir / form / sdir.name
            hit_dir.mkdir(parents=True, exist_ok=True)
            write_bytes(hit_dir / 'zone.bin', zone)
            (hit_dir / 'zone.hex.txt').write_text(zone.hex(), encoding='utf-8')

            if offs:
                for idx, off in enumerate(offs, 1):
                    seg = zone[off:off+ns.tail_len]
                    write_bytes(hit_dir / f'rid0D_at_{off:03d}.bin', seg)
                    (hit_dir / f'rid0D_at_{off:03d}.hex.txt').write_text(seg.hex(), encoding='utf-8')
                    rows.append({
                        'form': form,
                        'sample': sdir.name,
                        'rid0d_off_in_zone': off,
                        'rid0d_head8': seg[:8].hex(),
                    })
                    summary.append(f'  {sdir.name}: rid0D at zone+{off} head8={seg[:8].hex()}')
            else:
                rows.append({
                    'form': form,
                    'sample': sdir.name,
                    'rid0d_off_in_zone': '',
                    'rid0d_head8': '',
                })
                summary.append(f'  {sdir.name}: no rid0D marker found in zone')

        summary.append('')

    with (out_dir / 'flex_0d_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['form','sample','rid0d_off_in_zone','rid0d_head8'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({'rows': rows}, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
