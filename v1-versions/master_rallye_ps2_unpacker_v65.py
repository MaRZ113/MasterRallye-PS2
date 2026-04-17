#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

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

def main():
    ap = argparse.ArgumentParser(description='BX v65 exact packet template builder for rid0A 423f729a')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-exact-template')
    p.add_argument('v64_root', type=Path)
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-exact-template':
        raise SystemExit(1)

    v64_root: Path = ns.v64_root
    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    hit_dirs = sorted([p for p in v64_root.iterdir() if p.is_dir() and p.name.startswith('hit_')])
    if not hit_dirs:
        raise SystemExit('No hit_* dirs found in v64_root')

    packets = []
    rows = []
    for hdir in hit_dirs:
        rid0a = read_bytes(hdir / 'rid0A_253.bin')
        gap = read_bytes(hdir / 'gap_161.bin')
        rid0b = read_bytes(hdir / 'rid0B_9.bin')
        post = read_bytes(hdir / 'post0B_32.bin')
        packet = rid0a + gap + rid0b + post
        md5 = hashlib.md5(packet).hexdigest()
        packets.append(packet)
        rows.append({
            'hit': hdir.name,
            'rid0A_md5': hashlib.md5(rid0a).hexdigest(),
            'gap_md5': hashlib.md5(gap).hexdigest(),
            'rid0B_md5': hashlib.md5(rid0b).hexdigest(),
            'post_md5': hashlib.md5(post).hexdigest(),
            'packet_md5': md5,
            'packet_len': len(packet),
        })

    # verify exact identity across all packet samples
    unique_packets = {hashlib.md5(p).hexdigest() for p in packets}
    template = packets[0]

    write_bytes(out_dir / 'exact_packet_423f729a.bin', template)
    (out_dir / 'exact_packet_423f729a.hex.txt').write_text(template.hex(), encoding='utf-8')

    # search exact packet globally
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        offsets = find_all(mm, template)
        mm.close()

    with (out_dir / 'source_hit_components.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['hit','rid0A_md5','gap_md5','rid0B_md5','post_md5','packet_md5','packet_len']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    with (out_dir / 'exact_packet_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['index','off','off_hex']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for idx, off in enumerate(offsets, 1):
            w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

    summary = []
    summary.append('BX v65 exact 423f729a packet template')
    summary.append('====================================')
    summary.append(f'v64_root: {v64_root}')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'source_hits: {len(hit_dirs)}')
    summary.append(f'unique_packet_samples: {len(unique_packets)}')
    summary.append(f'exact_packet_len: {len(template)}')
    summary.append(f'exact_packet_md5: {hashlib.md5(template).hexdigest()}')
    summary.append(f'global_exact_hits: {len(offsets)}')
    summary.append('')
    summary.append('Global exact offsets:')
    for off in offsets[:32]:
        summary.append(f'  0x{off:X}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

    meta = {
        'unique_packet_samples': len(unique_packets),
        'exact_packet_len': len(template),
        'exact_packet_md5': hashlib.md5(template).hexdigest(),
        'global_exact_hits': len(offsets),
        'offsets': offsets[:256],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
