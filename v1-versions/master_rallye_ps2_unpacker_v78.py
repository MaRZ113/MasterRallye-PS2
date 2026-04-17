#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import difflib
import json
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap = argparse.ArgumentParser(description='BX v78 rid0C body resync mapper')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('map-rid0c-resync')
    p.add_argument('v77_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--min-block', type=int, default=8)

    ns = ap.parse_args()
    if ns.cmd != 'map-rid0c-resync':
        raise SystemExit(1)

    v77_root: Path = ns.v77_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    b1 = read_bytes(v77_root / 'variant1_body.bin')
    b2 = read_bytes(v77_root / 'variant2_body.bin')

    sm = difflib.SequenceMatcher(a=list(b1), b=list(b2), autojunk=False)
    blocks = sm.get_matching_blocks()

    summary = []
    summary.append('BX v78 rid0C body resync map')
    summary.append('============================')
    summary.append(f'v77_root: {v77_root}')
    summary.append(f'body_len_1: {len(b1)}')
    summary.append(f'body_len_2: {len(b2)}')
    summary.append(f'min_block: {ns.min_block}')
    summary.append('')

    match_rows = []
    kept = []
    for i, blk in enumerate(blocks, 1):
        if blk.size < ns.min_block:
            continue
        kept.append(blk)
        seg1 = b1[blk.a:blk.a+blk.size]
        write_bytes(out_dir / 'matches' / f'block_{i:02d}.bin', seg1)
        (out_dir / 'matches' / f'block_{i:02d}.hex.txt').write_text(seg1.hex(), encoding='utf-8')
        match_rows.append({
            'block': i,
            'a_off': blk.a,
            'b_off': blk.b,
            'len': blk.size,
            'delta_b_minus_a': blk.b - blk.a,
            'head16': seg1[:16].hex(),
        })
        summary.append(
            f'match {i:02d}: a={blk.a} b={blk.b} len={blk.size} delta={blk.b - blk.a} head16={seg1[:16].hex()}'
        )

    with (out_dir / 'matching_blocks.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['block','a_off','b_off','len','delta_b_minus_a','head16'])
        w.writeheader()
        w.writerows(match_rows)

    gap_rows = []
    for i in range(len(kept) - 1):
        cur = kept[i]
        nxt = kept[i + 1]

        a_gap_start = cur.a + cur.size
        b_gap_start = cur.b + cur.size

        a_len = max(0, nxt.a - (cur.a + cur.size))
        b_len = max(0, nxt.b - (cur.b + cur.size))

        seg1 = b1[a_gap_start:a_gap_start+a_len]
        seg2 = b2[b_gap_start:b_gap_start+b_len]

        write_bytes(out_dir / 'gaps' / f'gap_{i+1:02d}_variant1.bin', seg1)
        write_bytes(out_dir / 'gaps' / f'gap_{i+1:02d}_variant2.bin', seg2)
        (out_dir / 'gaps' / f'gap_{i+1:02d}_variant1.hex.txt').write_text(seg1.hex(), encoding='utf-8')
        (out_dir / 'gaps' / f'gap_{i+1:02d}_variant2.hex.txt').write_text(seg2.hex(), encoding='utf-8')

        gap_rows.append({
            'gap': i + 1,
            'a_start': a_gap_start,
            'a_len': a_len,
            'b_start': b_gap_start,
            'b_len': b_len,
            'delta_before': cur.b - cur.a,
            'delta_after': nxt.b - nxt.a,
            'variant1_head16': seg1[:16].hex(),
            'variant2_head16': seg2[:16].hex(),
        })

    with (out_dir / 'gap_map.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['gap','a_start','a_len','b_start','b_len','delta_before','delta_after','variant1_head16','variant2_head16']
        )
        w.writeheader()
        w.writerows(gap_rows)

    summary.append('')
    summary.append('Gap map:')
    for row in gap_rows:
        summary.append(
            f'gap {row["gap"]:02d}: a@{row["a_start"]} len={row["a_len"]} '
            f'b@{row["b_start"]} len={row["b_len"]} '
            f'delta {row["delta_before"]}->{row["delta_after"]}'
        )

    meta = {
        'body_len_1': len(b1),
        'body_len_2': len(b2),
        'matching_blocks_kept': len(match_rows),
        'gaps': len(gap_rows),
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
