#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import List, Dict

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

def load_rid08_bodies(v47_root: Path) -> List[Dict]:
    cdir = v47_root / 'comparative_rid_08'
    bodies = sorted(cdir.glob('*_body.bin'))
    items = []
    for p in bodies:
        fam = 'BXI1' if 'BXI1' in p.stem else 'BXI_'
        items.append({'name': p.stem, 'family': fam, 'data': read_bytes(p)})
    return items

def main():
    ap = argparse.ArgumentParser(description='BX v51 anchor-based rid08 splitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('split-rid08-anchor')
    p.add_argument('v47_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--offset', type=int, default=52)
    p.add_argument('--window', type=int, default=32)

    ns = ap.parse_args()
    if ns.cmd != 'split-rid08-anchor':
        raise SystemExit(1)

    root: Path = ns.v47_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    items = load_rid08_bodies(root)
    off = ns.offset
    win = ns.window

    summary = []
    summary.append('BX v51 rid08 anchor split')
    summary.append('=========================')
    summary.append(f'v47_root: {root}')
    summary.append(f'anchor_offset: {off}')
    summary.append(f'window: {win}')
    summary.append('')

    manifest_rows = []

    for item in items:
        data = item['data']
        sample_dir = out_dir / item['name']
        sample_dir.mkdir(parents=True, exist_ok=True)

        pre = data[:off]
        anchor = data[off:off+1] if off < len(data) else b''
        post = data[off+1:] if off+1 <= len(data) else b''
        left = max(0, off - win)
        right = min(len(data), off + 1 + win)
        around = data[left:right]

        write_bytes(sample_dir / 'body.bin', data)
        write_bytes(sample_dir / 'pre_anchor.bin', pre)
        write_bytes(sample_dir / 'anchor_byte.bin', anchor)
        write_bytes(sample_dir / 'post_anchor.bin', post)
        write_bytes(sample_dir / 'around_anchor.bin', around)

        (sample_dir / 'body.hex.txt').write_text(data.hex(), encoding='utf-8')
        (sample_dir / 'pre_anchor.hex.txt').write_text(pre.hex(), encoding='utf-8')
        (sample_dir / 'anchor_byte.hex.txt').write_text(anchor.hex(), encoding='utf-8')
        (sample_dir / 'post_anchor.hex.txt').write_text(post.hex(), encoding='utf-8')
        (sample_dir / 'around_anchor.hex.txt').write_text(around.hex(), encoding='utf-8')

        anchor_val = anchor.hex() if anchor else ''
        summary.append(
            f'{item["family"]} {item["name"]}: len={len(data)} anchor={anchor_val} '
            f'pre={len(pre)} post={len(post)} around={len(around)}'
        )

        manifest_rows.append({
            'sample': item['name'],
            'family': item['family'],
            'len': len(data),
            'anchor_off': off,
            'anchor_hex': anchor_val,
            'pre_len': len(pre),
            'post_len': len(post),
            'around_len': len(around),
        })

    summary.append('')

    compare_rows = []
    for i in range(len(items)):
        for j in range(i+1, len(items)):
            a = items[i]
            b = items[j]
            afull = a['data']
            bfull = b['data']
            apost = afull[off+1:] if off+1 <= len(afull) else b''
            bpost = bfull[off+1:] if off+1 <= len(bfull) else b''

            row = {
                'a': a['name'],
                'b': b['name'],
                'a_family': a['family'],
                'b_family': b['family'],
                'full_common_prefix': common_prefix_len(afull, bfull),
                'full_common_suffix': common_suffix_len(afull, bfull),
                'post_common_prefix': common_prefix_len(apost, bpost),
                'post_common_suffix': common_suffix_len(apost, bpost),
                'a_anchor': f'{afull[off]:02X}' if off < len(afull) else '',
                'b_anchor': f'{bfull[off]:02X}' if off < len(bfull) else '',
            }
            compare_rows.append(row)

    with (out_dir / 'sample_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['sample','family','len','anchor_off','anchor_hex','pre_len','post_len','around_len'])
        w.writeheader()
        w.writerows(manifest_rows)

    with (out_dir / 'pairwise_compare.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['a','b','a_family','b_family','full_common_prefix','full_common_suffix','post_common_prefix','post_common_suffix','a_anchor','b_anchor'])
        w.writeheader()
        w.writerows(compare_rows)

    bxi = [x for x in items if x['family'] == 'BXI_']
    if len(bxi) >= 2:
        a, b = bxi[0], bxi[1]
        apost = a['data'][off+1:] if off+1 <= len(a['data']) else b''
        bpost = b['data'][off+1:] if off+1 <= len(b['data']) else b''
        summary.append('BXI_ spotlight:')
        summary.append(
            f'  full_common_prefix={common_prefix_len(a["data"], b["data"])} '
            f'post_common_prefix={common_prefix_len(apost, bpost)} '
            f'full_common_suffix={common_suffix_len(a["data"], b["data"])} '
            f'post_common_suffix={common_suffix_len(apost, bpost)}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
