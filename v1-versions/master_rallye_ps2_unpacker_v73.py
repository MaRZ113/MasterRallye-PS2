#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

# Fixed internal chain discovered from the exact 2088-byte object
CHAIN = [
    ('09', 0,    323, b'\x00\x00\x01\x09'),
    ('0A', 323,  414, b'\x00\x00\x01\x0A'),
    ('0B', 737,  480, b'\x00\x00\x01\x0B'),
    ('0C', 1217, 507, b'\x00\x00\x01\x0C'),
    ('0D', 1724, 54,  b'\x00\x00\x01\x0D'),
]
TOTAL_LEN = 1778

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

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v73 09-0A-0B-0C-0D chain family miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-chain-families')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--max-export-per-family', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'mine-chain-families':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v73 09-0A-0B-0C-0D chain family miner')
    summary.append('=========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'chain_total_len: {TOTAL_LEN}')
    summary.append('')

    family_counter = Counter()
    family_hits = defaultdict(list)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        rid09_hits = find_all(mm, b'\x00\x00\x01\x09')

        for off in rid09_hits:
            # make sure the whole chain fits
            if off + TOTAL_LEN > mm.size():
                continue

            ok = True
            sigs = []
            for rid_hex, rel, ln, marker in CHAIN:
                if mm[off + rel : off + rel + 4] != marker:
                    ok = False
                    break
                rec = bytes(mm[off + rel : off + rel + ln])
                sig8 = rec[:8].hex()
                sigs.append(sig8)

            if not ok:
                continue

            fam_key = '|'.join(sigs)
            family_counter[fam_key] += 1
            if len(family_hits[fam_key]) < ns.max_export_per_family:
                family_hits[fam_key].append(off)

        mm.close()

    # write family counts
    with (out_dir / 'chain_family_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','count','fam_key','sig09','sig0A','sig0B','sig0C','sig0D'])
        w.writeheader()
        for rank, (fam_key, count) in enumerate(family_counter.most_common(), 1):
            parts = fam_key.split('|')
            w.writerow({
                'rank': rank,
                'count': count,
                'fam_key': fam_key,
                'sig09': parts[0],
                'sig0A': parts[1],
                'sig0B': parts[2],
                'sig0C': parts[3],
                'sig0D': parts[4],
            })

    summary.append(f'total_chain_hits: {sum(family_counter.values())}')
    summary.append(f'unique_chain_families: {len(family_counter)}')
    summary.append('')
    summary.append('Top chain families:')
    for fam_key, count in family_counter.most_common(12):
        parts = fam_key.split('|')
        summary.append(f'  count={count} 09={parts[0]} 0A={parts[1]} 0B={parts[2]} 0C={parts[3]} 0D={parts[4]}')
    summary.append('')

    # export representatives for top families
    fam_root = out_dir / 'families'
    fam_root.mkdir(exist_ok=True)

    manifest_rows = []
    for rank, (fam_key, count) in enumerate(family_counter.most_common(8), 1):
        parts = fam_key.split('|')
        fdir = fam_root / f'{rank:02d}'
        fdir.mkdir(parents=True, exist_ok=True)

        with (fdir / 'family_meta.json').open('w', encoding='utf-8') as f:
            json.dump({
                'rank': rank,
                'count': count,
                'fam_key': fam_key,
                'sig09': parts[0],
                'sig0A': parts[1],
                'sig0B': parts[2],
                'sig0C': parts[3],
                'sig0D': parts[4],
            }, f, indent=2)

        for idx, off in enumerate(family_hits[fam_key], 1):
            hdir = fdir / f'hit_{idx:02d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)
            block = carve(tng_path, off, TOTAL_LEN)
            write_bytes(hdir / 'chain_1778.bin', block)
            (hdir / 'chain_1778.hex.txt').write_text(block.hex(), encoding='utf-8')

            for rid_hex, rel, ln, marker in CHAIN:
                rec = block[rel:rel+ln]
                write_bytes(hdir / f'rid_{rid_hex}.bin', rec)
                (hdir / f'rid_{rid_hex}.hex.txt').write_text(rec.hex(), encoding='utf-8')

            manifest_rows.append({
                'family_rank': rank,
                'count': count,
                'off_hex': f'0x{off:X}',
                'sig09': parts[0],
                'sig0A': parts[1],
                'sig0B': parts[2],
                'sig0C': parts[3],
                'sig0D': parts[4],
            })

    with (out_dir / 'representative_chains.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_rank','count','off_hex','sig09','sig0A','sig0B','sig0C','sig0D'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
