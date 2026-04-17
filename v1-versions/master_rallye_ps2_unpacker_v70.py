#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

def read_offsets_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return [int(r['off']) for r in csv.DictReader(f)]

def longest_common_extension(mm: mmap.mmap, offsets, packet_len):
    # Grow backward
    back = 0
    while True:
        pos = offsets[0] - back - 1
        if pos < 0:
            break
        b = mm[pos]
        ok = True
        for off in offsets[1:]:
            p = off - back - 1
            if p < 0 or mm[p] != b:
                ok = False
                break
        if not ok:
            break
        back += 1

    # Grow forward
    fwd = 0
    while True:
        pos = offsets[0] + packet_len + fwd
        if pos >= mm.size():
            break
        b = mm[pos]
        ok = True
        for off in offsets[1:]:
            p = off + packet_len + fwd
            if p >= mm.size() or mm[p] != b:
                ok = False
                break
        if not ok:
            break
        fwd += 1

    return back, fwd

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

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

def main():
    ap = argparse.ArgumentParser(description='BX v70 maximal exact clone extent builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-max-clone')
    p.add_argument('tng_path', type=Path)
    p.add_argument('super_offsets_csv', type=Path)
    p.add_argument('superblock_bin', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-max-clone':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    offsets_csv: Path = ns.super_offsets_csv
    superblock_bin: Path = ns.superblock_bin
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    offsets = read_offsets_csv(offsets_csv)
    superblock = superblock_bin.read_bytes()
    packet_len = len(superblock)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        back, fwd = longest_common_extension(mm, offsets, packet_len)

        start0 = offsets[0] - back
        max_clone = mm[start0:start0 + back + packet_len + fwd]
        exact_offsets = find_all(mm, max_clone)
        mm.close()

    write_bytes(out_dir / 'max_clone.bin', max_clone)
    (out_dir / 'max_clone.hex.txt').write_text(max_clone.hex(), encoding='utf-8')

    # also split into before/super/after parts
    write_bytes(out_dir / 'max_clone_before.bin', max_clone[:back])
    write_bytes(out_dir / 'max_clone_superblock.bin', max_clone[back:back+packet_len])
    write_bytes(out_dir / 'max_clone_after.bin', max_clone[back+packet_len:])

    (out_dir / 'max_clone_before.hex.txt').write_text(max_clone[:back].hex(), encoding='utf-8')
    (out_dir / 'max_clone_superblock.hex.txt').write_text(max_clone[back:back+packet_len].hex(), encoding='utf-8')
    (out_dir / 'max_clone_after.hex.txt').write_text(max_clone[back+packet_len:].hex(), encoding='utf-8')

    with (out_dir / 'max_clone_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off','off_hex'])
        w.writeheader()
        for idx, off in enumerate(exact_offsets, 1):
            w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

    summary = []
    summary.append('BX v70 maximal exact clone extent')
    summary.append('===============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'source_offsets: {len(offsets)}')
    summary.append(f'superblock_len: {packet_len}')
    summary.append(f'common_back_extension: {back}')
    summary.append(f'common_forward_extension: {fwd}')
    summary.append(f'max_clone_len: {len(max_clone)}')
    summary.append(f'max_clone_md5: {hashlib.md5(max_clone).hexdigest()}')
    summary.append(f'global_exact_hits: {len(exact_offsets)}')
    summary.append('')
    summary.append('Global exact clone offsets:')
    for off in exact_offsets[:64]:
        summary.append(f'  0x{off:X}')

    meta = {
        'superblock_len': packet_len,
        'common_back_extension': back,
        'common_forward_extension': fwd,
        'max_clone_len': len(max_clone),
        'max_clone_md5': hashlib.md5(max_clone).hexdigest(),
        'global_exact_hits': len(exact_offsets),
        'offsets': exact_offsets[:256],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
