#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

COMPONENTS = [
    ('09', 'record_01_rid_09.bin'),
    ('0A', 'record_02_rid_0A.bin'),
    ('0B', 'record_03_rid_0B.bin'),
    ('0C', 'record_04_rid_0C.bin'),
    ('0D', 'record_05_rid_0D.bin'),
]

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def find_all(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def main():
    ap = argparse.ArgumentParser(description='BX v69 exact component reuse locator')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('locate-component-reuse')
    p.add_argument('v68_root', type=Path)
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'locate-component-reuse':
        raise SystemExit(1)

    v68_root: Path = ns.v68_root
    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v69 exact component reuse locator')
    summary.append('===================================')
    summary.append(f'v68_root: {v68_root}')
    summary.append(f'tng_path: {tng_path}')
    summary.append('')

    rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for rid_hex, fname in COMPONENTS:
            path = v68_root / fname
            blob = read_bytes(path)
            md5 = hashlib.md5(blob).hexdigest()
            offsets = find_all(mm, blob)

            comp_dir = out_dir / f'rid_{rid_hex}'
            comp_dir.mkdir(parents=True, exist_ok=True)

            with (comp_dir / 'offsets.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['index','off','off_hex'])
                w.writeheader()
                for idx, off in enumerate(offsets, 1):
                    w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

            meta = {
                'rid_hex': rid_hex,
                'file': fname,
                'len': len(blob),
                'md5': md5,
                'global_exact_hits': len(offsets),
                'offsets': offsets[:256],
            }
            (comp_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
            (comp_dir / 'record.bin').write_bytes(blob)
            (comp_dir / 'record.hex.txt').write_text(blob.hex(), encoding='utf-8')

            rows.append({
                'rid_hex': rid_hex,
                'len': len(blob),
                'md5': md5,
                'global_exact_hits': len(offsets),
            })

            summary.append(f'rid {rid_hex}: len={len(blob)} md5={md5} exact_hits={len(offsets)}')
            for off in offsets[:16]:
                summary.append(f'  0x{off:X}')
            summary.append('')

        mm.close()

    with (out_dir / 'component_reuse_summary.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rid_hex','len','md5','global_exact_hits'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
