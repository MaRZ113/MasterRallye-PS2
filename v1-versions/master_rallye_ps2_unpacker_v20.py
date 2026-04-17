#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Dict, List, Optional

CHAIN_RE = re.compile(r'^chain_(\d+)_')

def md5_file(p: Path) -> str:
    h = hashlib.md5()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def find_rid_bank_files(root: Path, rid: int, layer_hint: str) -> Dict[str, Path]:
    out = {}
    rid_dir = root / 'rid_banks' / f'rid_{rid:02d}_{layer_hint}'
    if not rid_dir.exists():
        return out
    for p in rid_dir.glob('*.bin'):
        m = CHAIN_RE.match(p.name)
        if m:
            out[m.group(1)] = p
    return out

def build_chain_map(root: Path) -> Dict[str, Dict[str, Optional[str]]]:
    rid1 = find_rid_bank_files(root, 1, 'header')
    rid2 = find_rid_bank_files(root, 2, 'header')
    all_ids = sorted(set(rid1) | set(rid2))
    result = {}
    for cid in all_ids:
        p1 = rid1.get(cid)
        p2 = rid2.get(cid)
        result[cid] = {
            'rid1_md5': md5_file(p1) if p1 else None,
            'rid2_md5': md5_file(p2) if p2 else None,
            'rid1_name': p1.name if p1 else None,
            'rid2_name': p2.name if p2 else None,
        }
        result[cid]['sig'] = f"{result[cid]['rid1_md5'] or 'none'}::{result[cid]['rid2_md5'] or 'none'}"
    return result

def copy_chain(root: Path, chain_id: str, dst: Path) -> None:
    src_chain = root / 'chains' / f'chain_{chain_id}'
    if src_chain.exists():
        shutil.copytree(src_chain, dst / f'chain_{chain_id}', dirs_exist_ok=True)

def run(full_root: Path, variant_root: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    full_map = build_chain_map(full_root)
    var_map = build_chain_map(variant_root)

    all_full_sigs = {v['sig'] for v in full_map.values()}
    all_var_sigs = {v['sig'] for v in var_map.values()}
    shared_sigs = all_full_sigs & all_var_sigs

    rows: List[dict] = []
    for fam, cmap in [('full', full_map), ('variant', var_map)]:
        for cid, info in sorted(cmap.items(), key=lambda kv: int(kv[0])):
            row = {
                'family': fam,
                'chain_id': cid,
                'sig': info['sig'],
                'rid1_md5': info['rid1_md5'],
                'rid2_md5': info['rid2_md5'],
                'rid1_name': info['rid1_name'],
                'rid2_name': info['rid2_name'],
                'shared_between_families': info['sig'] in shared_sigs,
            }
            rows.append(row)

    with (out_dir / 'chain_signatures.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [
            'family','chain_id','sig','rid1_md5','rid2_md5','rid1_name','rid2_name','shared_between_families'
        ])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # Group summary
    sig_to_members = {}
    for r in rows:
        sig_to_members.setdefault(r['sig'], []).append((r['family'], r['chain_id']))

    summary_lines = []
    summary_lines.append('BX v20 subfamily split')
    summary_lines.append('====================')
    summary_lines.append(f'full_root: {full_root}')
    summary_lines.append(f'variant_root: {variant_root}')
    summary_lines.append(f'full_chains: {len(full_map)}')
    summary_lines.append(f'variant_chains: {len(var_map)}')
    summary_lines.append(f'shared_signatures: {len(shared_sigs)}')
    summary_lines.append('')
    summary_lines.append('Signature groups:')
    for i, (sig, members) in enumerate(sorted(sig_to_members.items(), key=lambda kv: (len(kv[1]), kv[0]), reverse=True), 1):
        fams = ', '.join(f'{fam}:{cid}' for fam, cid in sorted(members))
        shared = 'yes' if sig in shared_sigs else 'no'
        summary_lines.append(f'grp_{i:03d} shared={shared} members={len(members)} :: {fams}')

    (out_dir / 'subfamily_summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')

    # Materialize groups
    groups_dir = out_dir / 'groups'
    groups_dir.mkdir(exist_ok=True)
    for i, (sig, members) in enumerate(sorted(sig_to_members.items(), key=lambda kv: (len(kv[1]), kv[0]), reverse=True), 1):
        gdir = groups_dir / f'grp_{i:03d}'
        gdir.mkdir(exist_ok=True)
        meta = {
            'sig': sig,
            'shared_between_families': sig in shared_sigs,
            'members': [{'family': fam, 'chain_id': cid} for fam, cid in members],
        }
        (gdir / 'group.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
        for fam, cid in members:
            if fam == 'full':
                copy_chain(full_root, cid, gdir / 'full')
            else:
                copy_chain(variant_root, cid, gdir / 'variant')

def main():
    ap = argparse.ArgumentParser(description='Split BX canonical families into subfamilies by RID 01/02 header signatures')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('split-subfamilies')
    p.add_argument('full_root', type=Path)
    p.add_argument('variant_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'split-subfamilies':
        run(ns.full_root, ns.variant_root, ns.out_dir)

if __name__ == '__main__':
    main()
