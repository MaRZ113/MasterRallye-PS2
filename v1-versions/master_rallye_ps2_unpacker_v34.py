#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path
from typing import List, Dict

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def common_prefix_len(a: bytes, b: bytes) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i

def find_all(mm: mmap.mmap, needle: bytes) -> List[int]:
    hits = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        hits.append(i)
        start = i + 1
    return hits

def carve_window(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def main():
    ap = argparse.ArgumentParser(description='BX v34 header-cluster locator')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('locate-header-clusters')
    p.add_argument('tng_path', type=Path)
    p.add_argument('seed_root', type=Path, help='v25_seed_schema')
    p.add_argument('out_dir', type=Path)
    p.add_argument('--pair-window', type=int, default=128)
    p.add_argument('--rid3-window', type=int, default=64)
    p.add_argument('--carve-size', type=int, default=512)

    ns = ap.parse_args()
    if ns.cmd != 'locate-header-clusters':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    seed_root: Path = ns.seed_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rid01 = read_bytes(seed_root / 'header_core' / 'rid_01.bin')
    rid02 = read_bytes(seed_root / 'header_core' / 'rid_02.bin')
    rid03_full = read_bytes(seed_root / 'rid_03_transition' / 'rid_03_full.bin')
    rid03_variant = read_bytes(seed_root / 'rid_03_transition' / 'rid_03_variant.bin')
    rid03_common = rid03_full[:common_prefix_len(rid03_full, rid03_variant)]

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid01_hits = find_all(mm, rid01)
        rid02_hits = find_all(mm, rid02)
        rid03_hits = find_all(mm, rid03_common) if rid03_common else []

        rid02_set = set(rid02_hits)
        rid03_set = set(rid03_hits)

        rows = []
        summary = []
        summary.append('BX v34 header-cluster locator')
        summary.append('============================')
        summary.append(f'tng_path: {tng_path}')
        summary.append(f'rid01_len: {len(rid01)}')
        summary.append(f'rid02_len: {len(rid02)}')
        summary.append(f'rid03_common_len: {len(rid03_common)}')
        summary.append(f'rid01_hits: {len(rid01_hits)}')
        summary.append(f'rid02_hits: {len(rid02_hits)}')
        summary.append(f'rid03_common_hits: {len(rid03_hits)}')
        summary.append('')

        # Pair rid01 -> rid02 within a short forward window
        idx = 0
        for off1 in rid01_hits:
            base_after_1 = off1 + len(rid01)
            candidate_rid2 = [o for o in rid02_hits if base_after_1 <= o <= base_after_1 + ns.pair_window]
            if not candidate_rid2:
                continue
            off2 = candidate_rid2[0]
            gap12 = off2 - base_after_1

            base_after_2 = off2 + len(rid02)
            candidate_rid3 = [o for o in rid03_hits if base_after_2 <= o <= base_after_2 + ns.rid3_window]
            off3 = candidate_rid3[0] if candidate_rid3 else None
            gap23 = (off3 - base_after_2) if off3 is not None else None

            idx += 1
            row = {
                'index': idx,
                'rid01_off': off1,
                'rid01_off_hex': f'0x{off1:X}',
                'rid02_off': off2,
                'rid02_off_hex': f'0x{off2:X}',
                'gap12': gap12,
                'rid03_common_off': off3 if off3 is not None else '',
                'rid03_common_off_hex': f'0x{off3:X}' if off3 is not None else '',
                'gap23': gap23 if gap23 is not None else '',
                'score': (1000 - gap12) + (1000 - gap23 if gap23 is not None else 0),
            }
            rows.append(row)

        rows.sort(key=lambda r: (int(r['gap12']), int(r['gap23']) if r['gap23'] != '' else 999999, -int(r['score'])))

        # Write outputs
        with (out_dir / 'header_cluster_hits.csv').open('w', encoding='utf-8', newline='') as f_csv:
            fieldnames = ['index','rid01_off','rid01_off_hex','rid02_off','rid02_off_hex','gap12','rid03_common_off','rid03_common_off_hex','gap23','score']
            w = csv.DictWriter(f_csv, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)

        summary.append(f'cluster_hits: {len(rows)}')
        summary.append('Top candidates:')
        for r in rows[:20]:
            summary.append(
                f"{r['index']:03d}) rid01={r['rid01_off_hex']} rid02={r['rid02_off_hex']} "
                f"gap12={r['gap12']} rid03={r['rid03_common_off_hex'] or 'n/a'} gap23={r['gap23'] if r['gap23'] != '' else 'n/a'}"
            )

        # carve top windows
        hits_dir = out_dir / 'top_windows'
        hits_dir.mkdir(exist_ok=True)
        for r in rows[:12]:
            start = max(0, int(r['rid01_off']) - 32)
            blob = carve_window(tng_path, start, ns.carve_size)
            hdir = hits_dir / f"hit_{int(r['index']):03d}_{r['rid01_off_hex']}"
            hdir.mkdir(exist_ok=True)
            (hdir / 'window.bin').write_bytes(blob)
            (hdir / 'window.hex.txt').write_text(blob.hex(), encoding='utf-8')
            meta = {
                'rid01_off': r['rid01_off'],
                'rid02_off': r['rid02_off'],
                'gap12': r['gap12'],
                'rid03_common_off': r['rid03_common_off'] if r['rid03_common_off'] != '' else None,
                'gap23': r['gap23'] if r['gap23'] != '' else None,
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
        mm.close()

if __name__ == '__main__':
    main()
