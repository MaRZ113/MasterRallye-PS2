#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
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
    ap = argparse.ArgumentParser(description='BX v79 rid0C normalized core extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-rid0c-core')
    p.add_argument('v77_root', type=Path)
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--min-block', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'extract-rid0c-core':
        raise SystemExit(1)

    v77_root: Path = ns.v77_root
    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    b1 = read_bytes(v77_root / 'variant1_body.bin')
    b2 = read_bytes(v77_root / 'variant2_body.bin')

    sm = difflib.SequenceMatcher(a=list(b1), b=list(b2), autojunk=False)
    blocks = [blk for blk in sm.get_matching_blocks() if blk.size >= ns.min_block and blk.size > 0]
    if not blocks:
        raise SystemExit('No matching blocks found')

    # take the dominant longest block
    best = max(blocks, key=lambda blk: blk.size)

    core = b1[best.a:best.a + best.size]
    v1_prefix = b1[:best.a]
    v1_suffix = b1[best.a + best.size:]
    v2_prefix = b2[:best.b]
    v2_suffix = b2[best.b + best.size:]

    write_bytes(out_dir / 'shared_core.bin', core)
    write_bytes(out_dir / 'variant1_prefix.bin', v1_prefix)
    write_bytes(out_dir / 'variant1_suffix.bin', v1_suffix)
    write_bytes(out_dir / 'variant2_prefix.bin', v2_prefix)
    write_bytes(out_dir / 'variant2_suffix.bin', v2_suffix)

    (out_dir / 'shared_core.hex.txt').write_text(core.hex(), encoding='utf-8')
    (out_dir / 'variant1_prefix.hex.txt').write_text(v1_prefix.hex(), encoding='utf-8')
    (out_dir / 'variant1_suffix.hex.txt').write_text(v1_suffix.hex(), encoding='utf-8')
    (out_dir / 'variant2_prefix.hex.txt').write_text(v2_prefix.hex(), encoding='utf-8')
    (out_dir / 'variant2_suffix.hex.txt').write_text(v2_suffix.hex(), encoding='utf-8')

    # search the normalized core globally
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        core_hits = find_all(mm, core)
        mm.close()

    with (out_dir / 'core_offsets.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off','off_hex'])
        w.writeheader()
        for idx, off in enumerate(core_hits, 1):
            w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

    summary = []
    summary.append('BX v79 rid0C normalized core')
    summary.append('============================')
    summary.append(f'v77_root: {v77_root}')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'body_len_1: {len(b1)}')
    summary.append(f'body_len_2: {len(b2)}')
    summary.append(f'best_match_a: {best.a}')
    summary.append(f'best_match_b: {best.b}')
    summary.append(f'best_match_len: {best.size}')
    summary.append(f'delta_b_minus_a: {best.b - best.a}')
    summary.append('')
    summary.append(f'variant1_prefix_len: {len(v1_prefix)}')
    summary.append(f'variant1_suffix_len: {len(v1_suffix)}')
    summary.append(f'variant2_prefix_len: {len(v2_prefix)}')
    summary.append(f'variant2_suffix_len: {len(v2_suffix)}')
    summary.append('')
    summary.append(f'shared_core_md5: {hashlib.md5(core).hexdigest()}')
    summary.append(f'global_core_hits: {len(core_hits)}')
    summary.append('Core offsets:')
    for off in core_hits[:64]:
        summary.append(f'  0x{off:X}')

    meta = {
        'best_match_a': best.a,
        'best_match_b': best.b,
        'best_match_len': best.size,
        'delta_b_minus_a': best.b - best.a,
        'variant1_prefix_len': len(v1_prefix),
        'variant1_suffix_len': len(v1_suffix),
        'variant2_prefix_len': len(v2_prefix),
        'variant2_suffix_len': len(v2_suffix),
        'shared_core_md5': hashlib.md5(core).hexdigest(),
        'global_core_hits': len(core_hits),
        'core_offsets': core_hits[:256],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
