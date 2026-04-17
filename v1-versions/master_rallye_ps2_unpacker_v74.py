#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

RECORD_LEN_0C = 507
DEFAULT_PREFIX = '0000010c423a'

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def read_summary_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs):
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs):
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def main():
    ap = argparse.ArgumentParser(description='BX v74 rid0C cousin family miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-cousins')
    p.add_argument('tng_path', type=Path)
    p.add_argument('rid0c_sig8_counts_csv', type=Path, help='v72_scout/rid_0C/sig8_counts.csv')
    p.add_argument('out_dir', type=Path)
    p.add_argument('--prefix', type=str, default=DEFAULT_PREFIX)
    p.add_argument('--max-export-per-sig8', type=int, default=3)
    p.add_argument('--top-sig8', type=int, default=12)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-cousins':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    sig8_counts_csv: Path = ns.rid0c_sig8_counts_csv
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = read_summary_csv(sig8_counts_csv)
    prefix = ns.prefix.lower()

    sig8_rows = [r for r in rows if r['sig8'].lower().startswith(prefix)]
    sig8_rows.sort(key=lambda r: int(r['count']), reverse=True)

    summary = []
    summary.append('BX v74 rid0C cousin family miner')
    summary.append('================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'prefix: {prefix}')
    summary.append(f'matching_sig8_families: {len(sig8_rows)}')
    summary.append('')

    with (out_dir / 'matching_sig8_counts.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['sig8','count']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(sig8_rows)

    fam_root = out_dir / 'sig8_families'
    fam_root.mkdir(exist_ok=True)
    family_rows = []

    import mmap
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for rank, r in enumerate(sig8_rows[:ns.top_sig8], 1):
            sig8 = r['sig8'].lower()
            count = int(r['count'])
            anchor = bytes.fromhex(sig8)
            hits = []
            start = 0
            while True:
                i = mm.find(anchor, start)
                if i == -1:
                    break
                if i + RECORD_LEN_0C <= mm.size():
                    hits.append(i)
                start = i + 1

            fdir = fam_root / f'{rank:02d}_{sig8}'
            fdir.mkdir(parents=True, exist_ok=True)

            blobs = []
            rep_hits = hits[:ns.max_export_per_sig8]
            for idx, off in enumerate(rep_hits, 1):
                blob = bytes(mm[off:off+RECORD_LEN_0C])
                blobs.append(blob)
                write_bytes(fdir / f'sample_{idx:02d}_0x{off:X}.bin', blob)
                (fdir / f'sample_{idx:02d}_0x{off:X}.hex.txt').write_text(blob.hex(), encoding='utf-8')

            cp = common_prefix_len(blobs)
            cs = common_suffix_len(blobs)

            if blobs:
                shared_head = blobs[0][:cp]
                write_bytes(fdir / 'shared_head.bin', shared_head)
                (fdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
                if cs > 0:
                    shared_tail = blobs[0][len(blobs[0]) - cs:]
                    write_bytes(fdir / 'shared_tail.bin', shared_tail)
                    (fdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

            with (fdir / 'family_meta.json').open('w', encoding='utf-8') as jf:
                json.dump({
                    'sig8': sig8,
                    'count': count,
                    'rescanned_hits': len(hits),
                    'representatives': len(rep_hits),
                    'shared_head_len': cp,
                    'shared_tail_len': cs,
                }, jf, indent=2)

            family_rows.append({
                'rank': rank,
                'sig8': sig8,
                'count': count,
                'rescanned_hits': len(hits),
                'shared_head_len': cp,
                'shared_tail_len': cs,
            })

            summary.append(f'{sig8}: count={count} rescanned_hits={len(hits)} shared_head={cp} shared_tail={cs}')

        mm.close()

    with (out_dir / 'family_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['rank','sig8','count','rescanned_hits','shared_head_len','shared_tail_len']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(family_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
