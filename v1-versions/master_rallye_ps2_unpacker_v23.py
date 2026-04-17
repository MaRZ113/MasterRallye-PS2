#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

def read_csv_rows(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def copy_if_exists(src: Path, dst: Path):
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

def run_extract(v22_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_lines = []
    manifest_rows = []

    groups = [p for p in v22_root.iterdir() if p.is_dir() and p.name.startswith('grp_')]
    groups = sorted(groups, key=lambda p: p.name)

    for g in groups:
        pt_csv = g / 'paired_template.csv'
        if not pt_csv.exists():
            continue
        rows = read_csv_rows(pt_csv)
        g_out = out_dir / g.name
        g_out.mkdir(parents=True, exist_ok=True)

        # layer buckets
        shared_header = g_out / 'shared_header_core'
        transition = g_out / 'transition_layer'
        divergence = g_out / 'divergence_layer'
        payload = g_out / 'payload_layer'

        same_header = 0
        total_rows = 0

        for r in rows:
            total_rows += 1
            rid = int(r['rid'])
            have_full = r['have_full'] == 'True'
            have_variant = r['have_variant'] == 'True'
            same = r['same'] == 'True'
            layer = r['layer']

            if rid == 16:
                continue

            # Source files in v22 layout
            if rid in (1,2):
                if same:
                    same_header += 1
                    src = g / 'shared_header' / f'rid_{rid:02d}.bin'
                    dst = shared_header / f'rid_{rid:02d}.bin'
                    copy_if_exists(src, dst)
                    manifest_rows.append({
                        'group': g.name, 'rid': rid, 'bucket': 'shared_header_core',
                        'same': same, 'layer': layer, 'source': str(src)
                    })
                else:
                    # defensive: if future data diverges, preserve both
                    for fam in ('full','variant'):
                        src = g / 'descriptor_layer' / f'rid_{rid:02d}_{fam}.bin'
                        dst = shared_header / f'rid_{rid:02d}_{fam}.bin'
                        copy_if_exists(src, dst)
                        manifest_rows.append({
                            'group': g.name, 'rid': rid, 'bucket': 'shared_header_core',
                            'same': same, 'layer': layer, 'source': str(src)
                        })
                continue

            # rid 03 = transition
            if rid == 3:
                for fam in ('full','variant'):
                    src = g / 'descriptor_layer' / f'rid_{rid:02d}_{fam}.bin'
                    dst = transition / f'rid_{rid:02d}_{fam}.bin'
                    copy_if_exists(src, dst)
                    manifest_rows.append({
                        'group': g.name, 'rid': rid, 'bucket': 'transition_layer',
                        'same': same, 'layer': layer, 'source': str(src)
                    })
                prev = g / 'descriptor_layer' / f'rid_{rid:02d}_preview.json'
                copy_if_exists(prev, transition / f'rid_{rid:02d}_preview.json')
                continue

            # rid 04-07 = descriptor divergence
            if 4 <= rid <= 7:
                for fam in ('full','variant'):
                    src = g / 'descriptor_layer' / f'rid_{rid:02d}_{fam}.bin'
                    dst = divergence / f'rid_{rid:02d}_{fam}.bin'
                    copy_if_exists(src, dst)
                    manifest_rows.append({
                        'group': g.name, 'rid': rid, 'bucket': 'divergence_layer',
                        'same': same, 'layer': layer, 'source': str(src)
                    })
                prev = g / 'descriptor_layer' / f'rid_{rid:02d}_preview.json'
                copy_if_exists(prev, divergence / f'rid_{rid:02d}_preview.json')
                continue

            # rid 08-15 = payload
            if 8 <= rid <= 15:
                for fam in ('full','variant'):
                    src = g / 'payload_layer' / f'rid_{rid:02d}_{fam}.bin'
                    dst = payload / f'rid_{rid:02d}_{fam}.bin'
                    copy_if_exists(src, dst)
                    manifest_rows.append({
                        'group': g.name, 'rid': rid, 'bucket': 'payload_layer',
                        'same': same, 'layer': layer, 'source': str(src)
                    })
                continue

        group_meta = {
            'group': g.name,
            'same_header_12': same_header,
            'transition_rid': 3,
            'descriptor_rids': [4,5,6,7],
            'payload_rids': [8,9,10,11,12,13,14,15],
        }
        (g_out / 'group_summary.json').write_text(json.dumps(group_meta, indent=2), encoding='utf-8')
        summary_lines.append(
            f"{g.name}: shared_header_core=rid01-02 transition=rid03 descriptor=rid04-07 payload=rid08-15 same_header_12={same_header}/2"
        )

    # global summary + manifest
    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')
    with (out_dir / 'paired_extractor_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['group','rid','bucket','same','layer','source']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in manifest_rows:
            w.writerow(row)

def main():
    ap = argparse.ArgumentParser(description='BX v23 paired extractor pass')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('extract-paired')
    p.add_argument('v22_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'extract-paired':
        run_extract(ns.v22_root, ns.out_dir)

if __name__ == '__main__':
    main()
