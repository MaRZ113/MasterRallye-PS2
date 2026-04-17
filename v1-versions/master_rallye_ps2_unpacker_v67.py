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
    ap = argparse.ArgumentParser(description='BX v67 exact super-block builder from rid09->rid0A423f729a context')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-superblock')
    p.add_argument('v66_root', type=Path)
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--prev-len', type=int, default=323, help='bytes from end of before.bin, aligned to prev rid09 marker')
    p.add_argument('--after-len', type=int, default=1000, help='shared after prefix to include')

    ns = ap.parse_args()
    if ns.cmd != 'build-superblock':
        raise SystemExit(1)

    v66_root: Path = ns.v66_root
    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    hit_dirs = sorted([p for p in v66_root.iterdir() if p.is_dir() and p.name.startswith('hit_')])
    if not hit_dirs:
        raise SystemExit('No hit_* dirs found in v66_root')

    # first hit defines the template; v66 already proved the contexts are identical in the used windows
    first = hit_dirs[0]
    before = read_bytes(first / 'before.bin')
    packet = read_bytes(first / 'packet.bin')
    after = read_bytes(first / 'after.bin')

    prev = before[-ns.prev_len:]
    aft = after[:ns.after_len]
    superblock = prev + packet + aft

    write_bytes(out_dir / 'rid09_323.bin', prev)
    write_bytes(out_dir / 'exact_packet_455.bin', packet)
    write_bytes(out_dir / 'after_1000.bin', aft)
    write_bytes(out_dir / 'exact_superblock_1778.bin', superblock)

    (out_dir / 'rid09_323.hex.txt').write_text(prev.hex(), encoding='utf-8')
    (out_dir / 'exact_packet_455.hex.txt').write_text(packet.hex(), encoding='utf-8')
    (out_dir / 'after_1000.hex.txt').write_text(aft.hex(), encoding='utf-8')
    (out_dir / 'exact_superblock_1778.hex.txt').write_text(superblock.hex(), encoding='utf-8')

    # verify components across all v66 hits
    comp_rows = []
    unique_prev = set()
    unique_packet = set()
    unique_after = set()
    unique_super = set()

    for hdir in hit_dirs:
        b = read_bytes(hdir / 'before.bin')
        p = read_bytes(hdir / 'packet.bin')
        a = read_bytes(hdir / 'after.bin')
        pv = b[-ns.prev_len:]
        af = a[:ns.after_len]
        sb = pv + p + af

        m_prev = hashlib.md5(pv).hexdigest()
        m_pack = hashlib.md5(p).hexdigest()
        m_after = hashlib.md5(af).hexdigest()
        m_super = hashlib.md5(sb).hexdigest()

        unique_prev.add(m_prev)
        unique_packet.add(m_pack)
        unique_after.add(m_after)
        unique_super.add(m_super)

        comp_rows.append({
            'hit': hdir.name,
            'rid09_md5': m_prev,
            'packet_md5': m_pack,
            'after_md5': m_after,
            'super_md5': m_super,
            'super_len': len(sb),
        })

    with (out_dir / 'component_identity.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['hit','rid09_md5','packet_md5','after_md5','super_md5','super_len'])
        w.writeheader()
        w.writerows(comp_rows)

    # global exact search
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        offsets = find_all(mm, superblock)
        mm.close()

    with (out_dir / 'exact_superblock_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off','off_hex'])
        w.writeheader()
        for idx, off in enumerate(offsets, 1):
            w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

    summary = []
    summary.append('BX v67 exact super-block template')
    summary.append('================================')
    summary.append(f'v66_root: {v66_root}')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'source_hits: {len(hit_dirs)}')
    summary.append(f'prev_len: {ns.prev_len}')
    summary.append(f'packet_len: {len(packet)}')
    summary.append(f'after_len: {ns.after_len}')
    summary.append(f'exact_superblock_len: {len(superblock)}')
    summary.append(f'unique_prev: {len(unique_prev)}')
    summary.append(f'unique_packet: {len(unique_packet)}')
    summary.append(f'unique_after: {len(unique_after)}')
    summary.append(f'unique_superblock: {len(unique_super)}')
    summary.append(f'exact_superblock_md5: {hashlib.md5(superblock).hexdigest()}')
    summary.append(f'global_exact_hits: {len(offsets)}')
    summary.append('')
    summary.append('Global exact super-block offsets:')
    for off in offsets[:64]:
        summary.append(f'  0x{off:X}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'prev_len': ns.prev_len,
        'packet_len': len(packet),
        'after_len': ns.after_len,
        'exact_superblock_len': len(superblock),
        'unique_prev': len(unique_prev),
        'unique_packet': len(unique_packet),
        'unique_after': len(unique_after),
        'unique_superblock': len(unique_super),
        'exact_superblock_md5': hashlib.md5(superblock).hexdigest(),
        'global_exact_hits': len(offsets),
        'offsets': offsets[:256],
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
