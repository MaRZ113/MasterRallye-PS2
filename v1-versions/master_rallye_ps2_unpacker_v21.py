#!/usr/bin/env python3
from __future__ import annotations

import argparse, csv, json, hashlib, shutil, re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

RID_RE = re.compile(r'rid_(\d+)_')

def md5_file(p: Path) -> str:
    h = hashlib.md5()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def list_group_members(group_dir: Path):
    for fam in ['full', 'variant']:
        fam_dir = group_dir / fam
        if fam_dir.exists():
            for chain_dir in fam_dir.glob('chain_*'):
                yield fam, chain_dir.name.split('_',1)[1], chain_dir

def gather_chain_payloads(chain_dir: Path) -> Dict[int, Path]:
    out = {}
    for layer in ['header','descriptor','data']:
        d = chain_dir / layer
        if d.exists():
            for p in d.glob('rid_*_*.bin'):
                m = RID_RE.search(p.name)
                if m:
                    out[int(m.group(1))] = p
    return out

def common_prefix_len(a: bytes, b: bytes) -> int:
    n=min(len(a),len(b))
    i=0
    while i<n and a[i]==b[i]:
        i+=1
    return i

def common_suffix_len(a: bytes, b: bytes) -> int:
    n=min(len(a),len(b))
    i=0
    while i<n and a[-1-i]==b[-1-i]:
        i+=1
    return i

def compare_two_files(a: Path, b: Path):
    ba=a.read_bytes(); bb=b.read_bytes()
    return {
        'len_a': len(ba),
        'len_b': len(bb),
        'md5_a': md5_file(a),
        'md5_b': md5_file(b),
        'same': ba==bb,
        'prefix': common_prefix_len(ba,bb),
        'suffix': common_suffix_len(ba,bb),
    }

def run(split_root: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows=[]
    summary=[]
    groups_root = split_root / 'groups'
    pair_groups=0
    unique_groups=0
    for group_dir in sorted(groups_root.glob('grp_*')):
        meta = json.loads((group_dir/'group.json').read_text(encoding='utf-8'))
        members = list(list_group_members(group_dir))
        fams = sorted(set(f for f,_,_ in members))
        if fams == ['full','variant']:
            pair_groups += 1
            full_member = next((m for m in members if m[0]=='full'), None)
            var_member = next((m for m in members if m[0]=='variant'), None)
            full_payloads = gather_chain_payloads(full_member[2])
            var_payloads = gather_chain_payloads(var_member[2])
            rids = sorted(set(full_payloads) | set(var_payloads))
            summary.append(f"{group_dir.name}: paired full:{full_member[1]} vs variant:{var_member[1]} shared={meta.get('shared_between_families')}")
            for rid in rids:
                fp = full_payloads.get(rid)
                vp = var_payloads.get(rid)
                rec = {
                    'group': group_dir.name,
                    'shared_sig': meta.get('shared_between_families'),
                    'full_chain': full_member[1],
                    'variant_chain': var_member[1],
                    'rid': rid,
                    'full_present': fp is not None,
                    'variant_present': vp is not None,
                }
                if fp and vp:
                    cmp = compare_two_files(fp,vp)
                    rec.update(cmp)
                    summary.append(
                        f"  rid {rid:02d}: same={cmp['same']} len_full={cmp['len_a']} len_var={cmp['len_b']} "
                        f"prefix={cmp['prefix']} suffix={cmp['suffix']}"
                    )
                rows.append(rec)
        else:
            unique_groups += 1
            summary.append(f"{group_dir.name}: unique {'/'.join(fams)} member_count={len(members)}")
            for fam,cid,cdir in members:
                payloads = gather_chain_payloads(cdir)
                for rid,p in sorted(payloads.items()):
                    rows.append({
                        'group': group_dir.name,
                        'shared_sig': meta.get('shared_between_families'),
                        'full_chain': cid if fam=='full' else '',
                        'variant_chain': cid if fam=='variant' else '',
                        'rid': rid,
                        'full_present': fam=='full',
                        'variant_present': fam=='variant',
                        'len_a': p.stat().st_size,
                        'len_b': None,
                        'md5_a': md5_file(p),
                        'md5_b': None,
                        'same': None,
                        'prefix': None,
                        'suffix': None,
                    })
    # write outputs
    with (out_dir/'paired_group_compare.csv').open('w', newline='', encoding='utf-8') as f:
        fn = ['group','shared_sig','full_chain','variant_chain','rid','full_present','variant_present','len_a','len_b','md5_a','md5_b','same','prefix','suffix']
        w=csv.DictWriter(f, fieldnames=fn); w.writeheader()
        for r in rows: w.writerow(r)
    text = []
    text.append("BX v21 paired-group compare")
    text.append("==========================")
    text.append(f"split_root: {split_root}")
    text.append(f"pair_groups: {pair_groups}")
    text.append(f"unique_groups: {unique_groups}")
    text.append("")
    text.extend(summary)
    (out_dir/'summary.txt').write_text('\n'.join(text), encoding='utf-8')

def main():
    ap=argparse.ArgumentParser(description='Compare paired subfamilies from v20_split group-by-group')
    sub=ap.add_subparsers(dest='cmd', required=True)
    p=sub.add_parser('compare-split')
    p.add_argument('split_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns=ap.parse_args()
    if ns.cmd=='compare-split':
        run(ns.split_root, ns.out_dir)

if __name__=='__main__':
    main()
