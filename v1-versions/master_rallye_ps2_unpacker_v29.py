#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import List, Dict

PRIMARY_DESC_RID = 7
PRIMARY_PAY_RID = 13
SECONDARY_DESC_RID = 6
SECONDARY_PAY_RID = 10

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))

def copy_if_exists(src: Path, dst: Path):
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

def collect_segments(v28_root: Path, layer: str) -> List[dict]:
    seg_rows = []
    seg_csv = v28_root / 'segment_manifest.csv'
    if not seg_csv.exists():
        raise FileNotFoundError(seg_csv)
    with seg_csv.open('r', encoding='utf-8', newline='') as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        if r['layer'] != layer:
            continue
        row = {k: (int(v) if k in ('seg_index','full_off','variant_off','full_len','variant_len') and v not in ('', None) else v)
               for k,v in r.items()}
        seg_rows.append(row)
    return seg_rows

def build_artifact_candidates(v28_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    descriptor_segs = collect_segments(v28_root, 'descriptor')
    payload_segs = collect_segments(v28_root, 'payload')

    # Rank payload segments by "interestingness"
    # Shared segments excluded; prioritize large replace/insert/delete blocks.
    cand_rows = []
    for row in payload_segs:
        if row['kind'] == 'shared':
            continue
        score = max(int(row.get('full_len', 0) or 0), int(row.get('variant_len', 0) or 0))
        if row['kind'] == 'replace':
            score += min(int(row.get('full_len', 0) or 0), int(row.get('variant_len', 0) or 0)) // 2
        cand_rows.append({
            **row,
            'score': score,
            'family_bias': 'variant' if int(row.get('variant_len', 0) or 0) > int(row.get('full_len', 0) or 0) else 'full',
        })
    cand_rows.sort(key=lambda r: (r['score'], abs(int(r.get('full_len',0) or 0) - int(r.get('variant_len',0) or 0))), reverse=True)

    # Also keep descriptor context from descriptor segments
    desc_rows_ranked = []
    for row in descriptor_segs:
        if row['kind'] == 'shared':
            continue
        score = max(int(row.get('full_len', 0) or 0), int(row.get('variant_len', 0) or 0))
        desc_rows_ranked.append({**row, 'score': score})
    desc_rows_ranked.sort(key=lambda r: r['score'], reverse=True)

    # Copy top candidates
    top_payload = cand_rows[:8]
    top_descriptor = desc_rows_ranked[:6]

    # source dirs
    desc_seg_root = v28_root / 'descriptor' / 'segments'
    pay_seg_root = v28_root / 'payload' / 'segments'

    manifest_rows = []
    summary = []
    summary.append('BX v29 first artifact candidates')
    summary.append('==============================')
    summary.append(f'focus_root: {v28_root}')
    summary.append('')
    summary.append('Top payload candidates:')
    for i, row in enumerate(top_payload, 1):
        seg_name = f"seg_{int(row['seg_index']):02d}_{row['kind']}"
        src = pay_seg_root / seg_name
        dst = out_dir / 'payload_candidates' / f'{i:02d}_{seg_name}'
        if src.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        summary.append(
            f"{i:02d}) {seg_name} full_len={row['full_len']} variant_len={row['variant_len']} "
            f"score={row['score']} family_bias={row['family_bias']}"
        )
        manifest_rows.append({
            'rank': i,
            'type': 'payload',
            'seg_name': seg_name,
            'kind': row['kind'],
            'full_len': row['full_len'],
            'variant_len': row['variant_len'],
            'score': row['score'],
            'family_bias': row['family_bias'],
        })

    summary.append('')
    summary.append('Top descriptor context segments:')
    for i, row in enumerate(top_descriptor, 1):
        seg_name = f"seg_{int(row['seg_index']):02d}_{row['kind']}"
        src = desc_seg_root / seg_name
        dst = out_dir / 'descriptor_context' / f'{i:02d}_{seg_name}'
        if src.exists():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        summary.append(
            f"{i:02d}) {seg_name} full_len={row['full_len']} variant_len={row['variant_len']} score={row['score']}"
        )
        manifest_rows.append({
            'rank': i,
            'type': 'descriptor',
            'seg_name': seg_name,
            'kind': row['kind'],
            'full_len': row['full_len'],
            'variant_len': row['variant_len'],
            'score': row['score'],
            'family_bias': '',
        })

    with (out_dir / 'artifact_candidate_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','type','seg_name','kind','full_len','variant_len','score','family_bias'])
        w.writeheader()
        w.writerows(manifest_rows)

    # Copy global context
    for name in ['summary.txt', 'hypothesis.json', 'segment_manifest.csv']:
        copy_if_exists(v28_root / name, out_dir / 'source_context' / name)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser(description='BX v29 first artifact candidate pack')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-artifact-candidates')
    p.add_argument('v28_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'build-artifact-candidates':
        build_artifact_candidates(ns.v28_root, ns.out_dir)

if __name__ == '__main__':
    main()
