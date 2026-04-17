#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
import re
from pathlib import Path

REC_RE = re.compile(b'\x00\x00\x01(.)', re.DOTALL)

PARTS = [
    ('preamble', 0, 310),
    ('rid09', 310, 323),
    ('rid0A', 633, 414),
    ('rid0B', 1047, 480),
    ('rid0C', 1527, 507),
    ('rid0D', 2034, 54),
]

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

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

def marker_offsets(data: bytes):
    return [(m.start(), f'{m.group(1)[0]:02X}') for m in REC_RE.finditer(data)]

def main():
    ap = argparse.ArgumentParser(description='BX v71 exact object passport for 2088-byte clone')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('passport-object')
    p.add_argument('v70_root', type=Path)
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'passport-object':
        raise SystemExit(1)

    v70_root: Path = ns.v70_root
    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    clone = read_bytes(v70_root / 'max_clone.bin')
    if len(clone) != 2088:
        # still work, but note it
        pass

    summary = []
    summary.append('BX v71 exact object passport')
    summary.append('===========================')
    summary.append(f'v70_root: {v70_root}')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'clone_len: {len(clone)}')
    summary.append(f'clone_md5: {hashlib.md5(clone).hexdigest()}')
    summary.append('')

    rows = []
    markers = marker_offsets(clone)
    summary.append(f'markers_in_clone: {markers}')
    summary.append('')

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for name, off, ln in PARTS:
            blob = clone[off:off+ln]
            pdir = out_dir / name
            pdir.mkdir(parents=True, exist_ok=True)

            write_bytes(pdir / f'{name}.bin', blob)
            (pdir / f'{name}.hex.txt').write_text(blob.hex(), encoding='utf-8')

            md5 = hashlib.md5(blob).hexdigest()
            offs = find_all(mm, blob)

            with (pdir / 'offsets.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(f_csv, fieldnames=['index','off','off_hex'])
                w.writeheader()
                for idx, o in enumerate(offs, 1):
                    w.writerow({'index': idx, 'off': o, 'off_hex': f'0x{o:X}'})

            meta = {
                'name': name,
                'off': off,
                'len': ln,
                'md5': md5,
                'global_exact_hits': len(offs),
                'head8': blob[:8].hex(),
                'tail8': blob[-8:].hex() if len(blob) >= 8 else blob.hex(),
                'markers': marker_offsets(blob),
            }
            (pdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            rows.append({
                'name': name,
                'off': off,
                'len': ln,
                'md5': md5,
                'global_exact_hits': len(offs),
                'head8': meta['head8'],
                'tail8': meta['tail8'],
                'marker_count': len(meta['markers']),
            })

            summary.append(
                f'{name}: off={off} len={ln} exact_hits={len(offs)} '
                f'head8={meta["head8"]} markers={meta["markers"]}'
            )

        mm.close()

    with (out_dir / 'object_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['name','off','len','md5','global_exact_hits','head8','tail8','marker_count'])
        w.writeheader()
        w.writerows(rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
