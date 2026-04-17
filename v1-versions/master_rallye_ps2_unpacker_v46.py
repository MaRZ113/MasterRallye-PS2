#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def copy_if_exists(src: Path, dst: Path):
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())

def main():
    ap = argparse.ArgumentParser(description='BX v46 nested decode pack / singleton artifact seed')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-nested-decode-pack')
    p.add_argument('v45_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-nested-decode-pack':
        raise SystemExit(1)

    root: Path = ns.v45_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v46 nested decode pack')
    summary.append('========================')
    summary.append(f'v45_root: {root}')
    summary.append('')

    manifest_rows = []

    # Comparative template targets
    for rid_hex in ['07', '08', '09']:
        rdir = root / f'rid_{rid_hex}'
        if not rdir.exists():
            continue

        out_r = out_dir / f'rid_{rid_hex}_comparative'
        out_r.mkdir(parents=True, exist_ok=True)

        # shared template pieces
        copy_if_exists(rdir / 'shared_head.bin', out_r / 'shared_head.bin')
        copy_if_exists(rdir / 'shared_head.hex.txt', out_r / 'shared_head.hex.txt')
        copy_if_exists(rdir / 'shared_tail.bin', out_r / 'shared_tail.bin')
        copy_if_exists(rdir / 'shared_tail.hex.txt', out_r / 'shared_tail.hex.txt')

        body_files = sorted(rdir.glob('*_body.bin'))
        kept = 0
        for bf in body_files:
            # For rid09, drop the obvious truncated outlier (very short body)
            if rid_hex == '09' and bf.stat().st_size < 32:
                continue
            copy_if_exists(bf, out_r / bf.name)
            copy_if_exists(Path(str(bf) + '.hex.txt'), out_r / (bf.name + '.hex.txt'))
            manifest_rows.append({
                'section': f'rid_{rid_hex}_comparative',
                'kind': 'body',
                'file': str((out_r / bf.name).relative_to(out_dir)),
                'len': bf.stat().st_size,
            })
            kept += 1

        summary.append(f'rid {rid_hex}: comparative bodies kept={kept}')
        if rid_hex == '07':
            summary.append('  role: best nested descriptor/start template')
        elif rid_hex == '08':
            summary.append('  role: best multi-sample nested payload candidate')
        elif rid_hex == '09':
            summary.append('  role: secondary payload-like record (outlier removed)')
        summary.append('')

    # Singleton artifact candidates
    for rid_hex in ['0A', '0B']:
        rdir = root / f'rid_{rid_hex}'
        if not rdir.exists():
            continue

        out_r = out_dir / f'rid_{rid_hex}_singleton'
        out_r.mkdir(parents=True, exist_ok=True)

        copy_if_exists(rdir / 'shared_head.bin', out_r / 'record.bin')
        copy_if_exists(rdir / 'shared_head.hex.txt', out_r / 'record.hex.txt')
        copy_if_exists(rdir / 'shared_tail.bin', out_r / 'shared_tail.bin')
        copy_if_exists(rdir / 'shared_tail.hex.txt', out_r / 'shared_tail.hex.txt')

        rec_path = out_r / 'record.bin'
        rec_len = rec_path.stat().st_size if rec_path.exists() else 0
        manifest_rows.append({
            'section': f'rid_{rid_hex}_singleton',
            'kind': 'record',
            'file': str(rec_path.relative_to(out_dir)) if rec_path.exists() else '',
            'len': rec_len,
        })

        summary.append(f'rid {rid_hex}: singleton record len={rec_len}')
        if rid_hex == '0A':
            summary.append('  role: best first standalone nested artifact candidate')
        elif rid_hex == '0B':
            summary.append('  role: tiny terminator-like nested tail')
        summary.append('')

    with (out_dir / 'decode_pack_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['section','kind','file','len'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
