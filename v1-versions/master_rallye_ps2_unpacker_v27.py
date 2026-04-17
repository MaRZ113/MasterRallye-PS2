#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

TARGETS = [
    # primary target
    {"descriptor_rid": 7, "payload_rid": 13, "label": "primary"},
    # secondary target
    {"descriptor_rid": 6, "payload_rid": 10, "label": "secondary"},
    # optional alternates
    {"descriptor_rid": 5, "payload_rid": 9, "label": "alternate_A"},
    {"descriptor_rid": 7, "payload_rid": 15, "label": "alternate_B"},
]

def copy_if_exists(src: Path, dst: Path):
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

def load_json(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))

def main():
    ap = argparse.ArgumentParser(description='BX v27 decode target pack builder')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-decode-pack')
    p.add_argument('seed_root', type=Path, help='v25_seed_schema directory')
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-decode-pack':
        raise SystemExit(1)

    seed_root: Path = ns.seed_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    summary_lines = []
    summary_lines.append('BX v27 decode target pack')
    summary_lines.append('=========================')
    summary_lines.append(f'seed_root: {seed_root}')
    summary_lines.append('')

    # Always include header core and transition
    header_dir = out_dir / 'header_core'
    transition_dir = out_dir / 'transition'
    for rid in (1, 2):
        src_bin = seed_root / 'header_core' / f'rid_{rid:02d}.bin'
        src_hex = seed_root / 'header_core' / f'rid_{rid:02d}.hex.txt'
        copy_if_exists(src_bin, header_dir / src_bin.name)
        copy_if_exists(src_hex, header_dir / src_hex.name)
        manifest_rows.append({'section': 'header_core', 'rid': rid, 'role': 'shared_header', 'file': src_bin.name})

    rid3_dir = seed_root / 'rid_03_transition'
    if rid3_dir.exists():
        for name in [
            'rid_03_full.bin', 'rid_03_variant.bin',
            'rid_03_full.hex.txt', 'rid_03_variant.hex.txt',
            'schema.json'
        ]:
            copy_if_exists(rid3_dir / name, transition_dir / name)
        manifest_rows.append({'section': 'transition', 'rid': 3, 'role': 'seed_transition', 'file': 'schema.json'})

    # Build target packs
    for target in TARGETS:
        drid = target['descriptor_rid']
        prid = target['payload_rid']
        label = target['label']

        dsrc = seed_root / f'rid_{drid:02d}_descriptor'
        psrc = seed_root / f'rid_{prid:02d}_payload'
        if not dsrc.exists() or not psrc.exists():
            continue

        tdir = out_dir / f'{label}_d{drid:02d}_p{prid:02d}'
        desc_dir = tdir / 'descriptor'
        pay_dir = tdir / 'payload'

        # Copy descriptor files
        for name in [
            f'rid_{drid:02d}_full.bin', f'rid_{drid:02d}_variant.bin',
            f'rid_{drid:02d}_full.hex.txt', f'rid_{drid:02d}_variant.hex.txt',
            'schema.json'
        ]:
            copy_if_exists(dsrc / name, desc_dir / name)

        # Copy payload files
        for name in [
            f'rid_{prid:02d}_full.bin', f'rid_{prid:02d}_variant.bin',
            f'rid_{prid:02d}_full.hex.txt', f'rid_{prid:02d}_variant.hex.txt',
            'schema.json'
        ]:
            copy_if_exists(psrc / name, pay_dir / name)

        d_schema = load_json(dsrc / 'schema.json')
        p_schema = load_json(psrc / 'schema.json')

        hypothesis = {
            'label': label,
            'descriptor_rid': drid,
            'payload_rid': prid,
            'descriptor_bucket': 'descriptor',
            'payload_bucket': 'payload',
            'descriptor_full_len': d_schema.get('full_len'),
            'descriptor_variant_len': d_schema.get('variant_len'),
            'descriptor_equal_ratio': d_schema.get('equal_ratio'),
            'descriptor_change_count': d_schema.get('change_count'),
            'payload_full_len': p_schema.get('full_len'),
            'payload_variant_len': p_schema.get('variant_len'),
            'payload_equal_ratio': p_schema.get('equal_ratio'),
            'payload_change_count': p_schema.get('change_count'),
            'notes': [
                'Look for local field changes near the first divergent segment in descriptor schema.',
                'Compare whether descriptor delta direction matches payload delta direction.',
                'Check if descriptor insert/delete blocks correlate with payload length deltas.',
            ],
        }
        (tdir / 'hypothesis.json').write_text(json.dumps(hypothesis, indent=2), encoding='utf-8')

        manifest_rows.append({'section': label, 'rid': drid, 'role': 'descriptor', 'file': 'schema.json'})
        manifest_rows.append({'section': label, 'rid': prid, 'role': 'payload', 'file': 'schema.json'})

        summary_lines.append(
            f'{label}: rid_{drid:02d} -> rid_{prid:02d} '
            f'desc_eq={d_schema.get("equal_ratio"):.4f} pay_eq={p_schema.get("equal_ratio"):.4f} '
            f'desc_delta={int(d_schema.get("full_len")) - int(d_schema.get("variant_len"))} '
            f'pay_delta={int(p_schema.get("full_len")) - int(p_schema.get("variant_len"))}'
        )

    # Manifest
    with (out_dir / 'decode_target_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['section', 'rid', 'role', 'file'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')

if __name__ == '__main__':
    main()
