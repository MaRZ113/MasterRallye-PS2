#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import List, Dict

def read_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def load_bytes(path: Path) -> bytes:
    return path.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v41 nested-BX artifact candidate builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-nested-candidates')
    p.add_argument('v40_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-nested-candidates':
        raise SystemExit(1)

    root: Path = ns.v40_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_csv(root / 'tail_fragment_manifest.csv')

    # Keep only large BX chunks as first artifact candidates.
    candidates = []
    for row in manifest:
        kind = row['segment_kind']
        ln = int(row['len'])
        if not kind.startswith('bx_chunk_'):
            continue
        if ln < 700:
            continue
        branch = row['branch']
        sample = row['sample']
        rel = row['file'].replace('\\', '/')
        candidates.append({
            'branch': branch,
            'sample': sample,
            'segment_kind': kind,
            'off': int(row['off']),
            'len': ln,
            'file': rel,
        })

    # Rank bigger first, then by branch/sample for stable order.
    candidates.sort(key=lambda r: (-r['len'], r['branch'], r['sample'], r['segment_kind']))

    summary = []
    summary.append('BX v41 nested-BX artifact candidates')
    summary.append('===================================')
    summary.append(f'v40_root: {root}')
    summary.append(f'candidate_count: {len(candidates)}')
    summary.append('')

    out_rows = []

    for idx, row in enumerate(candidates, 1):
        src = root / Path(row['file'])
        if not src.exists():
            # tolerate slash normalization
            src = root / row['file'].replace('/', '\\')
        data = load_bytes(src)

        cdir = out_dir / f'{idx:02d}_{row["branch"]}_{row["sample"]}_{row["segment_kind"]}'
        cdir.mkdir(parents=True, exist_ok=True)

        # raw candidate
        write_bytes(cdir / 'candidate.bin', data)
        (cdir / 'candidate.hex.txt').write_text(data.hex(), encoding='utf-8')

        # also split into head/body/tail for quicker manual decode
        head = data[:64]
        body = data[64:-64] if len(data) > 128 else b''
        tail = data[-64:] if len(data) > 64 else b''

        write_bytes(cdir / 'head64.bin', head)
        (cdir / 'head64.hex.txt').write_text(head.hex(), encoding='utf-8')

        if body:
            write_bytes(cdir / 'body.bin', body)
            (cdir / 'body.hex.txt').write_text(body.hex(), encoding='utf-8')

        if tail:
            write_bytes(cdir / 'tail64.bin', tail)
            (cdir / 'tail64.hex.txt').write_text(tail.hex(), encoding='utf-8')

        meta = {
            'rank': idx,
            **row,
            'head_len': len(head),
            'body_len': len(body),
            'tail_len': len(tail),
        }
        (cdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        out_rows.append({
            'rank': idx,
            **row,
        })

        summary.append(
            f'{idx:02d}) {row["branch"]} {row["sample"]} {row["segment_kind"]} len={row["len"]} off={row["off"]}'
        )

    with (out_dir / 'nested_candidate_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','branch','sample','segment_kind','off','len','file'])
        w.writeheader()
        w.writerows(out_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
