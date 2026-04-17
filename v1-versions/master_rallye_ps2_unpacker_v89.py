#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
import mmap
from pathlib import Path

RID0D = b'\x00\x00\x01\x0D'

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_all(data: bytes, needle: bytes):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def find_all_mm(mm: mmap.mmap, needle: bytes):
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
    ap = argparse.ArgumentParser(description='BX v89 rid0C latent/materialized companion mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-rid0c-companion')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v87_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--min-block', type=int, default=8)
    p.add_argument('--materialized-len', type=int, default=54)

    ns = ap.parse_args()
    if ns.cmd != 'map-rid0c-companion':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v87_root: Path = ns.v87_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    s_zone = read_bytes(v87_root / 'standalone_zone.bin')
    t_zone = read_bytes(v87_root / 'tailed_zone.bin')

    sm = difflib.SequenceMatcher(a=list(s_zone), b=list(t_zone), autojunk=False)
    blocks = [blk for blk in sm.get_matching_blocks() if blk.size >= ns.min_block and blk.size > 0]
    if len(blocks) < 2:
        raise SystemExit('Expected at least 2 matching blocks in v87 zones')

    # Choose the matching block that starts with 0d423f... if present, else the last/longest one
    companion_blk = None
    for blk in blocks:
        seg = s_zone[blk.a:blk.a+blk.size]
        if seg.startswith(bytes.fromhex('0d423f')):
            companion_blk = blk
            break
    if companion_blk is None:
        companion_blk = max(blocks, key=lambda blk: blk.size)

    companion_core = s_zone[companion_blk.a: companion_blk.a + companion_blk.size]

    # wrapper regions between previous matching block and companion block
    prev_blocks = [blk for blk in blocks if blk.a + blk.size <= companion_blk.a and blk.b + blk.size <= companion_blk.b]
    if prev_blocks:
        prev = max(prev_blocks, key=lambda blk: (blk.a + blk.size, blk.b + blk.size))
        s_wrap_start = prev.a + prev.size
        t_wrap_start = prev.b + prev.size
    else:
        s_wrap_start = 0
        t_wrap_start = 0

    s_wrapper = s_zone[s_wrap_start:companion_blk.a]
    t_wrapper = t_zone[t_wrap_start:companion_blk.b]

    # materialized 0D exact record in tailed zone
    offs_0d = find_all(t_zone, RID0D)
    materialized = b''
    off_0d = None
    if offs_0d:
        off_0d = offs_0d[0]
        materialized = t_zone[off_0d: off_0d + ns.materialized_len]

    # comparable standalone segment at same semantic join point = start of shared companion block
    latent54 = s_zone[companion_blk.a: companion_blk.a + ns.materialized_len]

    write_bytes(out_dir / 'standalone_zone.bin', s_zone)
    write_bytes(out_dir / 'tailed_zone.bin', t_zone)
    write_bytes(out_dir / 'shared_companion_core.bin', companion_core)
    write_bytes(out_dir / 'standalone_wrapper.bin', s_wrapper)
    write_bytes(out_dir / 'tailed_wrapper.bin', t_wrapper)
    write_bytes(out_dir / 'standalone_latent54.bin', latent54)
    if materialized:
        write_bytes(out_dir / 'tailed_materialized_0D54.bin', materialized)

    (out_dir / 'shared_companion_core.hex.txt').write_text(companion_core.hex(), encoding='utf-8')
    (out_dir / 'standalone_wrapper.hex.txt').write_text(s_wrapper.hex(), encoding='utf-8')
    (out_dir / 'tailed_wrapper.hex.txt').write_text(t_wrapper.hex(), encoding='utf-8')
    (out_dir / 'standalone_latent54.hex.txt').write_text(latent54.hex(), encoding='utf-8')
    if materialized:
        (out_dir / 'tailed_materialized_0D54.hex.txt').write_text(materialized.hex(), encoding='utf-8')

    # search globally
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        core_hits = find_all_mm(mm, companion_core)
        latent_hits = find_all_mm(mm, latent54)
        mat_hits = find_all_mm(mm, materialized) if materialized else []
        mm.close()

    with (out_dir / 'global_hits.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['label','count'])
        w.writeheader()
        w.writerow({'label': 'shared_companion_core', 'count': len(core_hits)})
        w.writerow({'label': 'standalone_latent54', 'count': len(latent_hits)})
        w.writerow({'label': 'tailed_materialized_0D54', 'count': len(mat_hits)})

    summary = []
    summary.append('BX v89 rid0C latent/materialized companion')
    summary.append('==========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'companion_a_off: {companion_blk.a}')
    summary.append(f'companion_b_off: {companion_blk.b}')
    summary.append(f'companion_len: {companion_blk.size}')
    summary.append(f'delta_b_minus_a: {companion_blk.b - companion_blk.a}')
    summary.append(f'standalone_wrapper_len: {len(s_wrapper)}')
    summary.append(f'tailed_wrapper_len: {len(t_wrapper)}')
    summary.append(f'tailed_0D_off: {off_0d if off_0d is not None else ""}')
    summary.append('')
    summary.append(f'shared_companion_core_md5: {hashlib.md5(companion_core).hexdigest()}')
    summary.append(f'standalone_latent54_md5: {hashlib.md5(latent54).hexdigest()}')
    if materialized:
        summary.append(f'tailed_materialized_0D54_md5: {hashlib.md5(materialized).hexdigest()}')
    summary.append('')
    summary.append(f'global_shared_companion_core_hits: {len(core_hits)}')
    summary.append(f'global_standalone_latent54_hits: {len(latent_hits)}')
    summary.append(f'global_tailed_materialized_0D54_hits: {len(mat_hits)}')
    summary.append('')
    summary.append(f'standalone_wrapper_hex: {s_wrapper.hex()}')
    summary.append(f'tailed_wrapper_hex: {t_wrapper.hex()}')
    if materialized:
        summary.append(f'tailed_materialized_head16: {materialized[:16].hex()}')
        summary.append(f'standalone_latent_head16: {latent54[:16].hex()}')

    meta = {
        'companion_a_off': companion_blk.a,
        'companion_b_off': companion_blk.b,
        'companion_len': companion_blk.size,
        'delta_b_minus_a': companion_blk.b - companion_blk.a,
        'standalone_wrapper_len': len(s_wrapper),
        'tailed_wrapper_len': len(t_wrapper),
        'tailed_0D_off': off_0d,
        'global_shared_companion_core_hits': len(core_hits),
        'global_standalone_latent54_hits': len(latent_hits),
        'global_tailed_materialized_0D54_hits': len(mat_hits),
    }
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
