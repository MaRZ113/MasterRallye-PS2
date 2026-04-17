#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Optional, Tuple


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def common_prefix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def common_suffix_len(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[-1 - i] == b[-1 - i]:
        i += 1
    return i


def find_rid_files(chain_root: Path) -> Dict[int, Path]:
    out: Dict[int, Path] = {}
    if not chain_root.exists():
        return out
    for p in chain_root.rglob('*.bin'):
        name = p.name
        if len(name) >= 7 and name.startswith('rid_') and name[4:6].isdigit():
            rid = int(name[4:6])
            out.setdefault(rid, p)
    return out


def load_pair(group_dir: Path) -> Optional[Tuple[Path, Path, dict]]:
    meta_path = group_dir / 'group.json'
    if not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text(encoding='utf-8'))
    members = meta.get('members', [])
    if len(members) != 2:
        return None
    fams = {m['family'] for m in members}
    if fams != {'full', 'variant'}:
        return None
    full_dirs = list((group_dir / 'full').glob('chain_*'))
    variant_dirs = list((group_dir / 'variant').glob('chain_*'))
    if len(full_dirs) != 1 or len(variant_dirs) != 1:
        return None
    return full_dirs[0], variant_dirs[0], meta


def run(split_root: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    groups_root = split_root / 'groups'
    summary_lines = []
    overall_rows = []

    for group_dir in sorted(groups_root.glob('grp_*')):
        pair = load_pair(group_dir)
        if not pair:
            continue
        full_chain, variant_chain, meta = pair
        rid_full = find_rid_files(full_chain)
        rid_var = find_rid_files(variant_chain)

        g_out = out_dir / group_dir.name
        g_out.mkdir(parents=True, exist_ok=True)
        shared_header_dir = g_out / 'shared_header'
        descriptor_dir = g_out / 'descriptor_layer'
        payload_dir = g_out / 'payload_layer'
        shared_header_dir.mkdir(exist_ok=True)
        descriptor_dir.mkdir(exist_ok=True)
        payload_dir.mkdir(exist_ok=True)

        rows = []
        for rid in range(1, 17):
            pf = rid_full.get(rid)
            pv = rid_var.get(rid)
            if not pf or not pv:
                rows.append({
                    'rid': rid, 'have_full': bool(pf), 'have_variant': bool(pv),
                    'same': False, 'len_full': None, 'len_variant': None,
                    'prefix': None, 'suffix': None, 'md5_full': None, 'md5_variant': None,
                    'layer': 'terminal' if rid == 16 else ('header' if rid <= 4 else ('descriptor' if rid <= 7 else 'data')),
                })
                continue
            bf = pf.read_bytes()
            bv = pv.read_bytes()
            same = bf == bv
            prefix = common_prefix_len(bf, bv)
            suffix = common_suffix_len(bf, bv)
            layer = 'terminal' if rid == 16 else ('header' if rid <= 4 else ('descriptor' if rid <= 7 else 'data'))
            row = {
                'rid': rid,
                'have_full': True,
                'have_variant': True,
                'same': same,
                'len_full': len(bf),
                'len_variant': len(bv),
                'prefix': prefix,
                'suffix': suffix,
                'md5_full': md5_bytes(bf),
                'md5_variant': md5_bytes(bv),
                'layer': layer,
            }
            rows.append(row)

            if rid in (1, 2) and same:
                (shared_header_dir / f'rid_{rid:02d}.bin').write_bytes(bf)
            elif rid <= 7:
                # write both sides and small hexdump preview
                (descriptor_dir / f'rid_{rid:02d}_full.bin').write_bytes(bf)
                (descriptor_dir / f'rid_{rid:02d}_variant.bin').write_bytes(bv)
                preview = {
                    'rid': rid,
                    'len_full': len(bf),
                    'len_variant': len(bv),
                    'prefix': prefix,
                    'suffix': suffix,
                    'full_hex_head': bf[:64].hex(),
                    'variant_hex_head': bv[:64].hex(),
                }
                (descriptor_dir / f'rid_{rid:02d}_preview.json').write_text(json.dumps(preview, indent=2), encoding='utf-8')
            elif rid <= 15:
                (payload_dir / f'rid_{rid:02d}_full.bin').write_bytes(bf)
                (payload_dir / f'rid_{rid:02d}_variant.bin').write_bytes(bv)

        with (g_out / 'paired_template.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)

        same12 = sum(1 for r in rows if r['rid'] in (1, 2) and r.get('same'))
        same_header = sum(1 for r in rows if r['layer'] == 'header' and r.get('same'))
        same_total = sum(1 for r in rows if r.get('same'))
        descriptor_change = [r for r in rows if r['layer'] == 'descriptor' and r['have_full'] and r['have_variant'] and not r['same']]
        payload_change = [r for r in rows if r['layer'] == 'data' and r['have_full'] and r['have_variant'] and not r['same']]

        summary_lines.append(f"{group_dir.name}: shared_header_12={same12}/2 shared_header_total={same_header}/4 same_total={same_total}/16 descriptor_changed={len(descriptor_change)} payload_changed={len(payload_change)}")

        for r in rows:
            rr = dict(r)
            rr['group'] = group_dir.name
            overall_rows.append(rr)

    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')
    if overall_rows:
        with (out_dir / 'paired_template_compare.csv').open('w', newline='', encoding='utf-8') as f:
            fieldnames = ['group'] + list(overall_rows[0].keys())[:-1] + ['layer']
            # preserve explicit order
            fieldnames = ['group', 'rid', 'have_full', 'have_variant', 'same', 'len_full', 'len_variant', 'prefix', 'suffix', 'md5_full', 'md5_variant', 'layer']
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in overall_rows:
                w.writerow(r)


def main() -> None:
    ap = argparse.ArgumentParser(description='BX v22 paired-template extractor for shared groups from v20 split')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('extract-paired-templates')
    p.add_argument('split_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'extract-paired-templates':
        run(ns.split_root, ns.out_dir)


if __name__ == '__main__':
    main()
