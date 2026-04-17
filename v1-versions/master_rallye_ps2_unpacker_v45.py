#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Dict

TARGET_RIDS = ['07', '08', '09', '0A', '0B']

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n:
        x = blobs[0][i]
        if any(b[i] != x for b in blobs[1:]):
            break
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n:
        x = blobs[0][-1-i]
        if any(b[-1-i] != x for b in blobs[1:]):
            break
        i += 1
    return i

def load_matrix_items(rid_dir: Path) -> List[dict]:
    csv_path = rid_dir / 'matrix.csv'
    if not csv_path.exists():
        return []
    with csv_path.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        name = r['name']
        # prefer reference.bin if same name exists, otherwise locate source in rid_banks
        # v44 writes reference.bin only for one sample; actual sample bins are in v43 rid_banks.
        out.append({'name': name, 'len': int(r['len'])})
    return out

def find_source_bin(v43_root: Path, rid_hex: str, name: str) -> Path:
    rid_dir = v43_root / 'rid_banks' / f'rid_{rid_hex}'
    # files in rid_banks are prefixed index + family + candidate + .bin
    for p in rid_dir.glob('*.bin'):
        if p.stem == name:
            return p
    raise FileNotFoundError(f'{rid_hex} {name}')

def main():
    ap = argparse.ArgumentParser(description='BX v45 nested chain template builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-nested-templates')
    p.add_argument('v44_root', type=Path)
    p.add_argument('v43_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-nested-templates':
        raise SystemExit(1)

    v44_root: Path = ns.v44_root
    v43_root: Path = ns.v43_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v45 nested chain templates')
    summary.append('============================')
    summary.append(f'v44_root: {v44_root}')
    summary.append(f'v43_root: {v43_root}')
    summary.append('')

    manifest_rows = []

    for rid_hex in TARGET_RIDS:
        rid_dir = v44_root / f'rid_{rid_hex}'
        if not rid_dir.exists():
            continue

        items_meta = load_matrix_items(rid_dir)
        blobs = []
        names = []
        for item in items_meta:
            src = find_source_bin(v43_root, rid_hex, item['name'])
            data = read_bytes(src)
            blobs.append(data)
            names.append(item['name'])

        if not blobs:
            continue

        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)
        r_out = out_dir / f'rid_{rid_hex}'
        r_out.mkdir(parents=True, exist_ok=True)

        shared_head = blobs[0][:cp]
        shared_tail = blobs[0][len(blobs[0]) - cs:] if cs > 0 else b''
        write_bytes(r_out / 'shared_head.bin', shared_head)
        (r_out / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
        if cs > 0:
            write_bytes(r_out / 'shared_tail.bin', shared_tail)
            (r_out / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

        summary.append(f'rid {rid_hex}: count={len(blobs)} shared_head={cp} shared_tail={cs}')

        for name, data in zip(names, blobs):
            body = data[cp: len(data)-cs if cs > 0 else len(data)]
            safe = name.replace('\\','_').replace('/','_')
            write_bytes(r_out / f'{safe}_body.bin', body)
            (r_out / f'{safe}_body.hex.txt').write_text(body.hex(), encoding='utf-8')
            manifest_rows.append({
                'rid': rid_hex,
                'sample': name,
                'full_len': len(data),
                'shared_head_len': cp,
                'body_len': len(body),
                'shared_tail_len': cs,
            })
            summary.append(f'  {name}: full={len(data)} body={len(body)}')

        # heuristic note
        if rid_hex == '07':
            summary.append('  note: best candidate for nested descriptor/start template')
        elif rid_hex == '08':
            summary.append('  note: likely second nested stage with branch-specific body')
        elif rid_hex == '09':
            summary.append('  note: payload-like, but one sample is truncated/outlier')
        elif rid_hex == '0A':
            summary.append('  note: only present in richest candidate, likely deep nested payload')
        elif rid_hex == '0B':
            summary.append('  note: terminator-like nested tail')
        summary.append('')

    with (out_dir / 'nested_template_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rid','sample','full_len','shared_head_len','body_len','shared_tail_len'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
