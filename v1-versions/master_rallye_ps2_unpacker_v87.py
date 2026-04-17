#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import json
from pathlib import Path

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
    while i < n and a[-1-i] == b[-1-i]:
        i += 1
    return i

def diff_runs(a: bytes, b: bytes):
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
    ap = argparse.ArgumentParser(description='BX v87 rid0C tail-zone normalization mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-rid0c-tailzone')
    p.add_argument('v86_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--min-block', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'map-rid0c-tailzone':
        raise SystemExit(1)

    v86_root: Path = ns.v86_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    standalone_dirs = sorted([p for p in (v86_root / 'standalone').iterdir() if p.is_dir()])
    tailed_dirs = sorted([p for p in (v86_root / 'tailed').iterdir() if p.is_dir()])

    if len(standalone_dirs) < 1 or len(tailed_dirs) < 1:
        raise SystemExit('Need at least one standalone and one tailed sample')

    sdir = standalone_dirs[0]
    tdir = tailed_dirs[0]

    s_gap = read_bytes(sdir / 'gap_314.bin')
    s_tail = read_bytes(sdir / 'tail_candidate_54.bin')
    s_post = read_bytes(sdir / 'post_tail.bin')
    t_gap = read_bytes(tdir / 'gap_314.bin')
    t_tail = read_bytes(tdir / 'tail_candidate_54.bin')
    t_post = read_bytes(tdir / 'post_tail.bin')

    s_zone = s_gap + s_tail + s_post
    t_zone = t_gap + t_tail + t_post

    cp = common_prefix_len(s_zone, t_zone)
    cs = common_suffix_len(s_zone, t_zone)

    sm = difflib.SequenceMatcher(a=list(s_zone), b=list(t_zone), autojunk=False)
    blocks = [blk for blk in sm.get_matching_blocks() if blk.size >= ns.min_block and blk.size > 0]
    runs = diff_runs(s_zone, t_zone)

    summary = []
    summary.append('BX v87 rid0C tail-zone normalization')
    summary.append('====================================')
    summary.append(f'standalone_dir: {sdir.name}')
    summary.append(f'tailed_dir: {tdir.name}')
    summary.append(f'standalone_zone_len: {len(s_zone)}')
    summary.append(f'tailed_zone_len: {len(t_zone)}')
    summary.append(f'common_prefix: {cp}')
    summary.append(f'common_suffix: {cs}')
    summary.append(f'matching_blocks: {len(blocks)}')
    summary.append(f'diff_runs: {len(runs)}')
    summary.append('')

    write_bytes(out_dir / 'standalone_zone.bin', s_zone)
    write_bytes(out_dir / 'tailed_zone.bin', t_zone)
    (out_dir / 'standalone_zone.hex.txt').write_text(s_zone.hex(), encoding='utf-8')
    (out_dir / 'tailed_zone.hex.txt').write_text(t_zone.hex(), encoding='utf-8')

    if cp > 0:
        write_bytes(out_dir / 'shared_prefix.bin', s_zone[:cp])
        (out_dir / 'shared_prefix.hex.txt').write_text(s_zone[:cp].hex(), encoding='utf-8')
    if cs > 0:
        write_bytes(out_dir / 'shared_suffix.bin', s_zone[len(s_zone)-cs:])
        (out_dir / 'shared_suffix.hex.txt').write_text(s_zone[len(s_zone)-cs:].hex(), encoding='utf-8')

    match_rows = []
    for idx, blk in enumerate(blocks, 1):
        seg = s_zone[blk.a:blk.a+blk.size]
        write_bytes(out_dir / 'matches' / f'block_{idx:02d}.bin', seg)
        (out_dir / 'matches' / f'block_{idx:02d}.hex.txt').write_text(seg.hex(), encoding='utf-8')
        match_rows.append({
            'block': idx,
            's_off': blk.a,
            't_off': blk.b,
            'len': blk.size,
            'delta_b_minus_a': blk.b - blk.a,
            'head16': seg[:16].hex(),
        })
        summary.append(
            f'match {idx:02d}: s={blk.a} t={blk.b} len={blk.size} delta={blk.b - blk.a} head16={seg[:16].hex()}'
        )

    with (out_dir / 'matching_blocks.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['block','s_off','t_off','len','delta_b_minus_a','head16'])
        w.writeheader()
        w.writerows(match_rows)

    run_rows = []
    for idx, (start, end) in enumerate(runs, 1):
        s_seg = s_zone[start:end+1] if start < len(s_zone) else b''
        t_seg = t_zone[start:end+1] if start < len(t_zone) else b''
        write_bytes(out_dir / 'diff_runs' / f'run_{idx:02d}_standalone.bin', s_seg)
        write_bytes(out_dir / 'diff_runs' / f'run_{idx:02d}_tailed.bin', t_seg)
        (out_dir / 'diff_runs' / f'run_{idx:02d}_standalone.hex.txt').write_text(s_seg.hex(), encoding='utf-8')
        (out_dir / 'diff_runs' / f'run_{idx:02d}_tailed.hex.txt').write_text(t_seg.hex(), encoding='utf-8')
        run_rows.append({
            'run': idx,
            'start': start,
            'end': end,
            'len': end - start + 1,
            'standalone_head16': s_seg[:16].hex(),
            'tailed_head16': t_seg[:16].hex(),
        })
        summary.append(
            f'run {idx:02d}: {start}-{end} len={end-start+1} '
            f's_head16={s_seg[:16].hex()} t_head16={t_seg[:16].hex()}'
        )

    with (out_dir / 'diff_runs.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['run','start','end','len','standalone_head16','tailed_head16'])
        w.writeheader()
        w.writerows(run_rows)

    meta = {
        'standalone_zone_md5': hashlib.md5(s_zone).hexdigest(),
        'tailed_zone_md5': hashlib.md5(t_zone).hexdigest(),
        'zone_len': len(s_zone),
        'common_prefix': cp,
        'common_suffix': cs,
        'matching_blocks': len(match_rows),
        'diff_runs': len(run_rows),
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
