#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List, Dict

TOP_FAMILIES = ['0000010a43', '0000010a42']

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs: List[bytes]) -> int:
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def load_family_hits(v55_root: Path, sig5: str) -> List[Dict]:
    reps_dir = v55_root / 'representatives'
    fam_dirs = [p for p in reps_dir.iterdir() if p.is_dir() and p.name.endswith(sig5)]
    if not fam_dirs:
        return []
    fam_dir = fam_dirs[0]
    items = []
    for hdir in sorted([p for p in fam_dir.iterdir() if p.is_dir()]):
        rec = hdir / 'rid0A_record_253.bin'
        meta = hdir / 'meta.json'
        if not rec.exists() or not meta.exists():
            continue
        items.append({
            'name': hdir.name,
            'data': read_bytes(rec),
            'meta': json.loads(meta.read_text(encoding='utf-8')),
        })
    return items

def pairwise_prefix_matrix(items: List[Dict]) -> List[Dict]:
    rows = []
    for i in range(len(items)):
        for j in range(i+1, len(items)):
            a = items[i]
            b = items[j]
            rows.append({
                'a': a['name'],
                'b': b['name'],
                'common_prefix': common_prefix_len([a['data'], b['data']]),
                'common_suffix': common_suffix_len([a['data'], b['data']]),
            })
    return rows

def main():
    ap = argparse.ArgumentParser(description='BX v56 rid0A family template builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-rid0a-families')
    p.add_argument('v55_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-rid0a-families':
        raise SystemExit(1)

    root: Path = ns.v55_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v56 rid0A family templates')
    summary.append('============================')
    summary.append(f'v55_root: {root}')
    summary.append('')

    family_meta = []

    loaded = {}
    for sig5 in TOP_FAMILIES:
        items = load_family_hits(root, sig5)
        loaded[sig5] = items
        if not items:
            continue

        blobs = [x['data'] for x in items]
        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)

        fdir = out_dir / f'fam_{sig5}'
        fdir.mkdir(parents=True, exist_ok=True)

        shared_head = blobs[0][:cp]
        shared_tail = blobs[0][len(blobs[0]) - cs:] if cs > 0 else b''

        write_bytes(fdir / 'shared_head.bin', shared_head)
        (fdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
        if cs > 0:
            write_bytes(fdir / 'shared_tail.bin', shared_tail)
            (fdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

        rows = []
        for item in items:
            body = item['data'][cp: len(item['data']) - cs if cs > 0 else len(item['data'])]
            safe = item['name'].replace('\\','_').replace('/','_')
            write_bytes(fdir / f'{safe}_body.bin', body)
            (fdir / f'{safe}_body.hex.txt').write_text(body.hex(), encoding='utf-8')
            rows.append({
                'sample': item['name'],
                'index': item['meta']['index'],
                'off_hex': item['meta']['off_hex'],
                'sig8': item['meta']['sig8'],
                'full_len': len(item['data']),
                'shared_head_len': cp,
                'body_len': len(body),
                'shared_tail_len': cs,
            })

        with (fdir / 'family_manifest.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['sample','index','off_hex','sig8','full_len','shared_head_len','body_len','shared_tail_len'])
            w.writeheader()
            w.writerows(rows)

        pair_rows = pairwise_prefix_matrix(items)
        with (fdir / 'pairwise_prefix.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['a','b','common_prefix','common_suffix'])
            w.writeheader()
            w.writerows(pair_rows)

        summary.append(f'{sig5}: samples={len(items)} shared_head={cp} shared_tail={cs}')
        for r in rows:
            summary.append(f'  {r["sample"]}: sig8={r["sig8"]} body={r["body_len"]}')
        summary.append('')
        family_meta.append({'sig5': sig5, 'sample_count': len(items), 'shared_head_len': cp, 'shared_tail_len': cs})

    # Cross-family comparison between shared heads
    if all(loaded.get(sig) for sig in TOP_FAMILIES):
        a = loaded[TOP_FAMILIES[0]]
        b = loaded[TOP_FAMILIES[1]]
        a_cp = common_prefix_len([x['data'] for x in a])
        b_cp = common_prefix_len([x['data'] for x in b])
        a_head = a[0]['data'][:a_cp]
        b_head = b[0]['data'][:b_cp]
        cross = common_prefix_len([a_head, b_head])

        cross_meta = {
            'fam_a': TOP_FAMILIES[0],
            'fam_b': TOP_FAMILIES[1],
            'fam_a_head_len': a_cp,
            'fam_b_head_len': b_cp,
            'cross_shared_head_len': cross,
        }
        (out_dir / 'cross_family_meta.json').write_text(json.dumps(cross_meta, indent=2), encoding='utf-8')
        summary.append(f'cross_family_shared_head: {cross} ({TOP_FAMILIES[0]} vs {TOP_FAMILIES[1]})')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'family_meta.json').write_text(json.dumps(family_meta, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
