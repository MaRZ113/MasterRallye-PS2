#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path
from typing import List, Dict

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def find_all(mm: mmap.mmap, needle: bytes) -> List[int]:
    hits = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        hits.append(i)
        start = i + 1
    return hits

def extract_bx_chain_tags(window: bytes) -> List[dict]:
    tags = []
    i = 0
    while True:
        j = window.find(b'BX', i)
        if j == -1:
            break
        tag = window[j:j+4]
        try:
            tag_ascii = tag.decode('latin1')
        except:
            tag_ascii = tag.hex()
        tags.append({'off': j, 'tag_ascii': tag_ascii})
        i = j + 1
    return tags

def main():
    ap = argparse.ArgumentParser(description='BX v35 physical header-cluster classifier')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('classify-header-clusters')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v34_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--carve-size', type=int, default=2048)

    ns = ap.parse_args()
    if ns.cmd != 'classify-header-clusters':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v34_root: Path = ns.v34_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    hits_csv = v34_root / 'header_cluster_hits.csv'
    if not hits_csv.exists():
        raise FileNotFoundError(hits_csv)

    rows = []
    with hits_csv.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))

    out_rows = []
    summary = []
    summary.append('BX v35 physical header-cluster classifier')
    summary.append('========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'v34_root: {v34_root}')
    summary.append(f'carve_size: {ns.carve_size}')
    summary.append('')

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for row in rows:
            idx = int(row['index'])
            rid01_off = int(row['rid01_off'])
            start = max(0, rid01_off - 32)
            blob = mm[start:start + ns.carve_size]

            tags = extract_bx_chain_tags(blob)
            rid1 = tags[0]['tag_ascii'] if len(tags) > 0 else ''
            rid2 = tags[1]['tag_ascii'] if len(tags) > 1 else ''
            rid3 = tags[2]['tag_ascii'] if len(tags) > 2 else ''
            rid4 = tags[3]['tag_ascii'] if len(tags) > 3 else ''
            signature = '|'.join([t for t in (rid1, rid2, rid3, rid4) if t])

            kind = 'cluster_4plus' if len(tags) >= 4 else ('cluster_3' if len(tags) == 3 else 'short')

            out_rows.append({
                'index': idx,
                'rid01_off': rid01_off,
                'rid01_off_hex': row['rid01_off_hex'],
                'rid02_off_hex': row['rid02_off_hex'],
                'rid03_common_off_hex': row.get('rid03_common_off_hex', ''),
                'gap12': row['gap12'],
                'gap23': row['gap23'],
                'kind': kind,
                'bx_count_in_window': len(tags),
                'rid1_tag': rid1,
                'rid2_tag': rid2,
                'rid3_tag': rid3,
                'rid4_tag': rid4,
                'signature_4': signature,
            })

            # materialize candidate window
            hdir = out_dir / 'clusters' / f'hit_{idx:03d}_{row["rid01_off_hex"]}'
            hdir.mkdir(parents=True, exist_ok=True)
            (hdir / 'window.bin').write_bytes(blob)
            (hdir / 'window.hex.txt').write_text(blob.hex(), encoding='utf-8')
            (hdir / 'tags.json').write_text(json.dumps(tags, indent=2), encoding='utf-8')

        mm.close()

    # sort by strongest physical evidence
    out_rows.sort(key=lambda r: (
        0 if str(r['gap23']) not in ('', 'nan') else 1,
        -int(r['bx_count_in_window']),
        r['signature_4'],
        int(r['rid01_off'])
    ))

    with (out_dir / 'classified_clusters.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = list(out_rows[0].keys()) if out_rows else []
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(out_rows)

    # summary stats by rid4
    rid4_counts = {}
    sig_counts = {}
    for r in out_rows:
        rid4_counts[r['rid4_tag']] = rid4_counts.get(r['rid4_tag'], 0) + 1
        sig_counts[r['signature_4']] = sig_counts.get(r['signature_4'], 0) + 1

    summary.append(f'total_clusters: {len(out_rows)}')
    summary.append('rid4 distribution:')
    for k, v in sorted(rid4_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        summary.append(f'  {k or "<none>"}: {v}')
    summary.append('')
    summary.append('top signatures:')
    for k, v in sorted(sig_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]:
        summary.append(f'  {k}: {v}')

    summary.append('')
    summary.append('top candidates:')
    for r in out_rows[:12]:
        summary.append(
            f'{r["index"]:03d}) {r["rid01_off_hex"]} sig={r["signature_4"]} '
            f'gap12={r["gap12"]} gap23={r["gap23"]} bx_count={r["bx_count_in_window"]}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
