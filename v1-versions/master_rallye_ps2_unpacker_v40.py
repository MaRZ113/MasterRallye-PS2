#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

def find_all(data: bytes, needle: bytes = b'BX') -> List[int]:
    hits = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        hits.append(i)
        start = i + 1
    return hits

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def read_bytes(path: Path) -> bytes:
    return path.read_bytes()

def split_tail(tail: bytes, bx_offs: List[int]):
    segs = []
    if not bx_offs:
        segs.append({'kind': 'whole_tail', 'off': 0, 'len': len(tail)})
        return segs

    # pre-BX header
    if bx_offs[0] > 0:
        segs.append({'kind': 'pre_bx', 'off': 0, 'len': bx_offs[0]})

    # BX windows between successive BX markers
    for i, off in enumerate(bx_offs):
        end = bx_offs[i+1] if i+1 < len(bx_offs) else len(tail)
        segs.append({'kind': f'bx_chunk_{i+1}', 'off': off, 'len': end - off})

    return segs

def process_branch(branch_dir: Path, out_dir: Path, summary_lines: List[str], manifest_rows: List[dict]):
    branch_name = branch_dir.name
    tails = sorted(branch_dir.glob('*/tail.bin'))
    if not tails:
        return

    summary_lines.append(f'[{branch_name}]')
    bx_pos_rows = []

    for tail_path in tails:
        sample = tail_path.parent.name
        data = read_bytes(tail_path)
        offs = find_all(data, b'BX')
        bx_pos_rows.append({'sample': sample, 'bx_offsets': offs, 'tail_len': len(data)})
        summary_lines.append(f'  {sample}: len={len(data)} bx_offsets={offs}')

        # segment tail
        segs = split_tail(data, offs)
        sdir = out_dir / branch_name / sample
        for seg in segs:
            blob = data[seg['off']: seg['off'] + seg['len']]
            name = f'{seg["kind"]}.bin'
            write_bytes(sdir / name, blob)
            (sdir / (name + '.hex.txt')).write_text(blob.hex(), encoding='utf-8')
            manifest_rows.append({
                'branch': branch_name,
                'sample': sample,
                'segment_kind': seg['kind'],
                'off': seg['off'],
                'len': seg['len'],
                'file': str((sdir / name).relative_to(out_dir)),
            })

    # write branch summary + offsets CSV
    bdir = out_dir / branch_name
    bdir.mkdir(parents=True, exist_ok=True)
    with (bdir / 'bx_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sample','tail_len','bx_offsets_json'])
        w.writeheader()
        for row in bx_pos_rows:
            w.writerow({
                'sample': row['sample'],
                'tail_len': row['tail_len'],
                'bx_offsets_json': json.dumps(row['bx_offsets']),
            })

def main():
    ap = argparse.ArgumentParser(description='BX v40 tail BX mapper / fragment splitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-tail-bx')
    p.add_argument('v39_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'map-tail-bx':
        raise SystemExit(1)

    root: Path = ns.v39_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    branches = [p for p in root.iterdir() if p.is_dir() and p.name.startswith('branch_')]
    branches = sorted(branches)

    summary_lines = []
    summary_lines.append('BX v40 tail BX mapper')
    summary_lines.append('====================')
    summary_lines.append(f'v39_root: {root}')
    summary_lines.append('')

    manifest_rows = []

    for b in branches:
        process_branch(b, out_dir, summary_lines, manifest_rows)
        summary_lines.append('')

    with (out_dir / 'tail_fragment_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['branch','sample','segment_kind','off','len','file'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')

if __name__ == '__main__':
    main()
