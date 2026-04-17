#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

DEFAULT_FAMILY = '08_0000010c423a4a02'

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
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def main():
    ap = argparse.ArgumentParser(description='BX v75 rid0C family field miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-family')
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--family', type=str, default=DEFAULT_FAMILY)
    p.add_argument('--probe-body-len', type=int, default=128)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-family':
        raise SystemExit(1)

    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_dir = v74_root / 'sig8_families' / ns.family
    if not fam_dir.exists():
        raise SystemExit(f'Family dir not found: {fam_dir}')

    sample_paths = sorted([p for p in fam_dir.glob('sample_*.bin')])
    blobs = [read_bytes(p) for p in sample_paths]
    if not blobs:
        raise SystemExit('No sample_*.bin files in family dir')

    cp = common_prefix_len(blobs)
    cs = common_suffix_len(blobs)

    summary = []
    summary.append('BX v75 rid0C family field miner')
    summary.append('===============================')
    summary.append(f'family: {ns.family}')
    summary.append(f'samples: {len(blobs)}')
    summary.append(f'shared_head_len: {cp}')
    summary.append(f'shared_tail_len: {cs}')
    summary.append('')

    shared_head = blobs[0][:cp]
    write_bytes(out_dir / 'shared_head.bin', shared_head)
    (out_dir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')

    if cs > 0:
        shared_tail = blobs[0][len(blobs[0]) - cs:]
        write_bytes(out_dir / 'shared_tail.bin', shared_tail)
        (out_dir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

    manifest_rows = []
    bodies = []
    for p, blob in zip(sample_paths, blobs):
        body = blob[cp: len(blob)-cs if cs > 0 else len(blob)]
        bodies.append(body)
        stem = p.stem
        write_bytes(out_dir / f'{stem}_body.bin', body)
        (out_dir / f'{stem}_body.hex.txt').write_text(body.hex(), encoding='utf-8')
        manifest_rows.append({
            'sample': stem,
            'full_len': len(blob),
            'shared_head_len': cp,
            'body_len': len(body),
            'shared_tail_len': cs,
            'head16': blob[:16].hex(),
            'body_head16': body[:16].hex(),
        })
        summary.append(f'{stem}: body_len={len(body)} body_head16={body[:16].hex()}')

    with (out_dir / 'family_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['sample','full_len','shared_head_len','body_len','shared_tail_len','head16','body_head16']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(manifest_rows)

    probe_len = min(ns.probe_body_len, min(len(b) for b in bodies))
    byte_rows = []
    cand_rows = []

    for off in range(probe_len):
        vals = [b[off] for b in bodies]
        uniq = len(set(vals))
        row = {'off': off, 'uniq_values': uniq}
        for idx, v in enumerate(vals, 1):
            row[f's{idx}'] = f'{v:02X}'
        byte_rows.append(row)

        if uniq <= 2:
            cnt = {}
            for v in vals:
                cnt[v] = cnt.get(v, 0) + 1
            cand_rows.append({
                'off': off,
                'uniq_values': uniq,
                'values': ' '.join(f'{k:02X}:{v}' for k, v in sorted(cnt.items())),
            })

    with (out_dir / 'body_byte_atlas.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(byte_rows[0].keys())
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(byte_rows)

    with (out_dir / 'candidate_body_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off','uniq_values','values']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(cand_rows)

    summary.append('')
    summary.append('Top low-variability body offsets:')
    for row in cand_rows[:40]:
        summary.append(f'  off={row["off"]} uniq={row["uniq_values"]} values={row["values"]}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'family': ns.family,
        'samples': len(blobs),
        'shared_head_len': cp,
        'shared_tail_len': cs,
        'probe_len': probe_len,
        'candidate_offsets': cand_rows[:256],
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
