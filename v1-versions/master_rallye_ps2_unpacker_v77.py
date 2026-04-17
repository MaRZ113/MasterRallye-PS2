#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Tuple

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i

def common_suffix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[-1 - i] == b[-1 - i]:
        i += 1
    return i

def diff_runs(a: bytes, b: bytes) -> List[Tuple[int, int]]:
    n = min(len(a), len(b))
    runs = []
    start = None
    for i in range(n):
        same = a[i] == b[i]
        if not same and start is None:
            start = i
        elif same and start is not None:
            runs.append((start, i - 1))
            start = None
    if start is not None:
        runs.append((start, n - 1))
    if len(a) != len(b):
        runs.append((n, max(len(a), len(b)) - 1))
    return runs

def main():
    ap = argparse.ArgumentParser(description='BX v77 rid0C body variant diff mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-rid0c-variant-diff')
    p.add_argument('v76_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'map-rid0c-variant-diff':
        raise SystemExit(1)

    v76_root: Path = ns.v76_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    var_root = v76_root / 'body_variants'
    if not var_root.exists():
        raise SystemExit(f'No body_variants dir in {v76_root}')

    variant_dirs = sorted([p for p in var_root.iterdir() if p.is_dir()])
    if len(variant_dirs) < 2:
        raise SystemExit('Need at least 2 body variants')

    # variant 01 = dominant, variant 02 = alternate
    v1 = variant_dirs[0]
    v2 = variant_dirs[1]

    s1 = sorted(v1.glob('sample_*.bin'))[0]
    s2 = sorted(v2.glob('sample_*.bin'))[0]

    b1 = read_bytes(s1)
    b2 = read_bytes(s2)

    cp = common_prefix_len(b1, b2)
    cs = common_suffix_len(b1, b2)
    runs = diff_runs(b1, b2)

    summary = []
    summary.append('BX v77 rid0C body variant diff map')
    summary.append('==================================')
    summary.append(f'variant_1: {v1.name} :: {s1.name}')
    summary.append(f'variant_2: {v2.name} :: {s2.name}')
    summary.append(f'body_len_1: {len(b1)}')
    summary.append(f'body_len_2: {len(b2)}')
    summary.append(f'common_prefix: {cp}')
    summary.append(f'common_suffix: {cs}')
    summary.append(f'diff_run_count: {len(runs)}')
    summary.append('')

    write_bytes(out_dir / 'variant1_body.bin', b1)
    write_bytes(out_dir / 'variant2_body.bin', b2)
    (out_dir / 'variant1_body.hex.txt').write_text(b1.hex(), encoding='utf-8')
    (out_dir / 'variant2_body.hex.txt').write_text(b2.hex(), encoding='utf-8')

    if cp > 0:
        write_bytes(out_dir / 'shared_prefix.bin', b1[:cp])
        (out_dir / 'shared_prefix.hex.txt').write_text(b1[:cp].hex(), encoding='utf-8')
    if cs > 0:
        write_bytes(out_dir / 'shared_suffix.bin', b1[len(b1)-cs:])
        (out_dir / 'shared_suffix.hex.txt').write_text(b1[len(b1)-cs:].hex(), encoding='utf-8')

    diff_rows = []
    for idx, (start, end) in enumerate(runs, 1):
        seg1 = b1[start:end+1] if start < len(b1) else b''
        seg2 = b2[start:end+1] if start < len(b2) else b''
        ddir = out_dir / 'diff_runs'
        ddir.mkdir(exist_ok=True)
        write_bytes(ddir / f'run_{idx:02d}_variant1.bin', seg1)
        write_bytes(ddir / f'run_{idx:02d}_variant2.bin', seg2)
        (ddir / f'run_{idx:02d}_variant1.hex.txt').write_text(seg1.hex(), encoding='utf-8')
        (ddir / f'run_{idx:02d}_variant2.hex.txt').write_text(seg2.hex(), encoding='utf-8')

        diff_rows.append({
            'run': idx,
            'start': start,
            'end': end,
            'len': end - start + 1,
            'variant1_head16': seg1[:16].hex(),
            'variant2_head16': seg2[:16].hex(),
        })
        summary.append(
            f'run {idx:02d}: {start}-{end} len={end-start+1} '
            f'v1_head16={seg1[:16].hex()} v2_head16={seg2[:16].hex()}'
        )

    with (out_dir / 'diff_runs.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['run','start','end','len','variant1_head16','variant2_head16'])
        w.writeheader()
        w.writerows(diff_rows)

    # byte-level atlas for first 128 bytes of body
    atlas_rows = []
    probe_len = min(128, len(b1), len(b2))
    for off in range(probe_len):
        atlas_rows.append({
            'off': off,
            'v1': f'{b1[off]:02X}',
            'v2': f'{b2[off]:02X}',
            'same': 1 if b1[off] == b2[off] else 0,
        })

    with (out_dir / 'byte_diff_atlas_first128.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','v1','v2','same'])
        w.writeheader()
        w.writerows(atlas_rows)

    meta = {
        'variant1_dir': v1.name,
        'variant2_dir': v2.name,
        'body_len_1': len(b1),
        'body_len_2': len(b2),
        'common_prefix': cp,
        'common_suffix': cs,
        'diff_run_count': len(runs),
        'diff_runs': [{'start': s, 'end': e, 'len': e-s+1} for s, e in runs],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
