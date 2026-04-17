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

def read_manifest(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def main():
    ap = argparse.ArgumentParser(description='BX v94 sibling family latent/materialized mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-sibling-companion')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v93_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--materialized-len', type=int, default=54)
    p.add_argument('--min-block', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'map-sibling-companion':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v93_root: Path = ns.v93_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_manifest(v93_root / 'tail_probe_manifest.csv')
    standalone_rows = [r for r in manifest if r['tail_candidate_is_0D'] == '0']
    tailed_rows = [r for r in manifest if r['tail_candidate_is_0D'] == '1']
    if not standalone_rows or not tailed_rows:
        raise SystemExit('Need both standalone and tailed sibling samples')

    # pick first of each
    s_off = standalone_rows[0]['off_hex']
    t_off = tailed_rows[0]['off_hex']
    sdir = v93_root / s_off
    tdir = v93_root / t_off

    s_gap = read_bytes(sdir / 'tail_gap.bin')
    s_tail = read_bytes(sdir / 'tail_candidate.bin')
    s_post = read_bytes(sdir / 'tail_post.bin')
    t_gap = read_bytes(tdir / 'tail_gap.bin')
    t_tail = read_bytes(tdir / 'tail_candidate.bin')
    t_post = read_bytes(tdir / 'tail_post.bin')

    s_zone = s_gap + s_tail + s_post
    t_zone = t_gap + t_tail + t_post

    sm = difflib.SequenceMatcher(a=list(s_zone), b=list(t_zone), autojunk=False)
    blocks = [blk for blk in sm.get_matching_blocks() if blk.size >= ns.min_block and blk.size > 0]

    # choose block starting with 0d423f if possible, else longest
    chosen = None
    for blk in blocks:
        seg = s_zone[blk.a:blk.a + blk.size]
        if seg.startswith(bytes.fromhex('0d423f')):
            chosen = blk
            break
    if chosen is None:
        chosen = max(blocks, key=lambda blk: blk.size)

    shared_core = s_zone[chosen.a:chosen.a + chosen.size]
    s_latent54 = s_zone[chosen.a: chosen.a + ns.materialized_len]
    t_materialized54 = b''
    offs_0d = find_all(t_zone, RID0D)
    t_0d_off = offs_0d[0] if offs_0d else None
    if t_0d_off is not None:
        t_materialized54 = t_zone[t_0d_off:t_0d_off + ns.materialized_len]

    # wrappers = bytes between end of previous match and start of chosen match
    prev_blocks = [blk for blk in blocks if blk.a + blk.size <= chosen.a and blk.b + blk.size <= chosen.b]
    if prev_blocks:
        prev = max(prev_blocks, key=lambda blk: (blk.a + blk.size, blk.b + blk.size))
        s_wrap_start = prev.a + prev.size
        t_wrap_start = prev.b + prev.size
    else:
        s_wrap_start = 0
        t_wrap_start = 0

    s_wrapper = s_zone[s_wrap_start:chosen.a]
    t_wrapper = t_zone[t_wrap_start:chosen.b]

    write_bytes(out_dir / 'standalone_zone.bin', s_zone)
    write_bytes(out_dir / 'tailed_zone.bin', t_zone)
    write_bytes(out_dir / 'shared_companion_core.bin', shared_core)
    write_bytes(out_dir / 'standalone_wrapper.bin', s_wrapper)
    write_bytes(out_dir / 'tailed_wrapper.bin', t_wrapper)
    write_bytes(out_dir / 'standalone_latent54.bin', s_latent54)
    if t_materialized54:
        write_bytes(out_dir / 'tailed_materialized_0D54.bin', t_materialized54)

    # search globally
    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        core_hits = find_all_mm(mm, shared_core)
        latent_hits = find_all_mm(mm, s_latent54)
        mat_hits = find_all_mm(mm, t_materialized54) if t_materialized54 else []
        mm.close()

    with (out_dir / 'global_hits.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['label','count'])
        w.writeheader()
        w.writerow({'label': 'shared_companion_core', 'count': len(core_hits)})
        w.writerow({'label': 'standalone_latent54', 'count': len(latent_hits)})
        w.writerow({'label': 'tailed_materialized_0D54', 'count': len(mat_hits)})

    summary = []
    summary.append('BX v94 sibling family latent/materialized companion')
    summary.append('===============================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'standalone_sample: {s_off}')
    summary.append(f'tailed_sample: {t_off}')
    summary.append(f'companion_a_off: {chosen.a}')
    summary.append(f'companion_b_off: {chosen.b}')
    summary.append(f'companion_len: {chosen.size}')
    summary.append(f'delta_b_minus_a: {chosen.b - chosen.a}')
    summary.append(f'tailed_0D_off: {t_0d_off if t_0d_off is not None else ""}')
    summary.append('')
    summary.append(f'shared_companion_core_md5: {md5(shared_core)}')
    summary.append(f'standalone_latent54_md5: {md5(s_latent54)}')
    if t_materialized54:
        summary.append(f'tailed_materialized_0D54_md5: {md5(t_materialized54)}')
    summary.append('')
    summary.append(f'global_shared_companion_core_hits: {len(core_hits)}')
    summary.append(f'global_standalone_latent54_hits: {len(latent_hits)}')
    summary.append(f'global_tailed_materialized_0D54_hits: {len(mat_hits)}')
    summary.append('')
    summary.append(f'standalone_wrapper_hex: {s_wrapper.hex()}')
    summary.append(f'tailed_wrapper_hex: {t_wrapper.hex()}')
    if t_materialized54:
        summary.append(f'standalone_latent_head16: {s_latent54[:16].hex()}')
        summary.append(f'tailed_materialized_head16: {t_materialized54[:16].hex()}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'companion_a_off': chosen.a,
        'companion_b_off': chosen.b,
        'companion_len': chosen.size,
        'delta_b_minus_a': chosen.b - chosen.a,
        'tailed_0D_off': t_0d_off,
        'global_shared_companion_core_hits': len(core_hits),
        'global_standalone_latent54_hits': len(latent_hits),
        'global_tailed_materialized_0D54_hits': len(mat_hits),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
