#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

REC_RE = re.compile(b'\x00\x00\x01(.)', re.DOTALL)

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_records(data: bytes):
    hits = []
    for m in REC_RE.finditer(data):
        rid = data[m.start()+3]
        hits.append((m.start(), rid))
    return hits

def main():
    ap = argparse.ArgumentParser(description='BX v68 super-chain splitter for exact 1778-byte block')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('split-superchain')
    p.add_argument('v67_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'split-superchain':
        raise SystemExit(1)

    v67_root: Path = ns.v67_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    sb = read_bytes(v67_root / 'exact_superblock_1778.bin')
    hits = find_records(sb)

    summary = []
    summary.append('BX v68 exact super-chain split')
    summary.append('==============================')
    summary.append(f'v67_root: {v67_root}')
    summary.append(f'superblock_len: {len(sb)}')
    summary.append(f'record_count: {len(hits)}')
    summary.append('')

    rows = []

    for i, (off, rid) in enumerate(hits):
        end = hits[i+1][0] if i+1 < len(hits) else len(sb)
        blob = sb[off:end]
        rid_hex = f'{rid:02X}'
        name = f'record_{i+1:02d}_rid_{rid_hex}.bin'
        write_bytes(out_dir / name, blob)
        (out_dir / (name + '.hex.txt')).write_text(blob.hex(), encoding='utf-8')

        row = {
            'index': i+1,
            'rid_hex': rid_hex,
            'off': off,
            'len': len(blob),
            'head8': blob[:8].hex(),
            'tail8': blob[-8:].hex() if len(blob) >= 8 else blob.hex(),
            'file': name,
        }
        rows.append(row)
        summary.append(
            f'{i+1:02d}) rid=0x{rid_hex} off={off} len={len(blob)} head8={row["head8"]}'
        )

    with (out_dir / 'superchain_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','rid_hex','off','len','head8','tail8','file'])
        w.writeheader()
        w.writerows(rows)

    meta = {
        'superblock_len': len(sb),
        'record_count': len(hits),
        'records': [{'off': off, 'rid': rid} for off, rid in hits],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
