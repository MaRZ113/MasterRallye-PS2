#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, hashlib, json, math, os, statistics
from pathlib import Path
from collections import Counter, defaultdict

def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def common_prefix(blobs):
    if not blobs: return 0
    m=min(len(b) for b in blobs)
    for i in range(m):
        x=blobs[0][i]
        if any(b[i]!=x for b in blobs[1:]):
            return i
    return m

def common_suffix(blobs):
    if not blobs: return 0
    m=min(len(b) for b in blobs)
    for i in range(1,m+1):
        x=blobs[0][-i]
        if any(b[-i]!=x for b in blobs[1:]):
            return i-1
    return m

def collect(profile_dir: Path):
    rows=[]
    rid_banks=defaultdict(list)
    for p in profile_dir.rglob('*.bin'):
        parts=p.parts
        if 'rid_banks' not in parts: continue
        # ... rid_banks/rid_05_descriptor/file.bin
        idx=parts.index('rid_banks')
        group=parts[idx+1]
        file=p.name
        if not group.startswith('rid_'): continue
        seg=group.split('_',2)
        rid=int(seg[1]); role=seg[2]
        data=p.read_bytes()
        rid_banks[(rid,role)].append((file,data))
    for (rid,role), lst in sorted(rid_banks.items()):
        blobs=[d for _,d in lst]
        lens=[len(b) for b in blobs]
        ents=[entropy(b) for b in blobs]
        rows.append({
            'rid': rid,
            'role': role,
            'count': len(blobs),
            'min_len': min(lens),
            'med_len': statistics.median(lens),
            'max_len': max(lens),
            'common_prefix': common_prefix(blobs),
            'common_suffix': common_suffix(blobs),
            'med_entropy': statistics.median(ents),
            'unique_md5': len({hashlib.md5(b).hexdigest() for b in blobs}),
        })
    return rows

def compare(full_dir: Path, variant_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    full_rows=collect(full_dir)
    var_rows=collect(variant_dir)
    by_full={(r['rid'],r['role']):r for r in full_rows}
    by_var={(r['rid'],r['role']):r for r in var_rows}
    keys=sorted(set(by_full)|set(by_var))
    out=[]
    for k in keys:
        a=by_full.get(k,{}); b=by_var.get(k,{})
        rid,role=k
        out.append({
            'rid': rid,'role': role,
            'full_count': a.get('count'),'variant_count': b.get('count'),
            'full_med_len': a.get('med_len'),'variant_med_len': b.get('med_len'),
            'full_prefix': a.get('common_prefix'),'variant_prefix': b.get('common_prefix'),
            'full_suffix': a.get('common_suffix'),'variant_suffix': b.get('common_suffix'),
            'full_med_entropy': a.get('med_entropy'),'variant_med_entropy': b.get('med_entropy'),
            'full_unique_md5': a.get('unique_md5'),'variant_unique_md5': b.get('unique_md5'),
            'len_delta': (a.get('med_len') or 0) - (b.get('med_len') or 0),
            'entropy_delta': round((a.get('med_entropy') or 0) - (b.get('med_entropy') or 0), 6),
        })
    with (out_dir/'rid_bank_compare.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
    # rank candidates
    struct=[]; data=[]
    for r in out:
        rid=r['rid']
        avgp=((r['full_prefix'] or 0)+(r['variant_prefix'] or 0))/2
        avgent=((r['full_med_entropy'] or 0)+(r['variant_med_entropy'] or 0))/2
        if rid<=7:
            struct.append((rid,r['role'],avgp,avgent,r['len_delta']))
        else:
            data.append((rid,r['role'],avgp,avgent,r['len_delta']))
    struct_sorted=sorted(struct, key=lambda x:(-x[2], x[3], abs(x[4])))
    data_sorted=sorted(data, key=lambda x:(-abs(x[4]), -x[3], x[2]))
    lines=[]
    lines.append('BX v14 rid-bank compare')
    lines.append('======================')
    lines.append(f'full_profile: {full_dir}')
    lines.append(f'variant_profile: {variant_dir}')
    lines.append('')
    lines.append('Most structural header/descriptor candidates:')
    for rid,role,p,e,ld in struct_sorted:
        lines.append(f'rid {rid:02d} [{role}] prefix_avg={p:.1f} ent_avg={e:.3f} len_delta={ld}')
    lines.append('')
    lines.append('Most payload-distinct data candidates:')
    for rid,role,p,e,ld in data_sorted:
        lines.append(f'rid {rid:02d} [{role}] |len_delta|={abs(ld)} ent_avg={e:.3f} prefix_avg={p:.1f} raw_len_delta={ld}')
    (out_dir/'summary.txt').write_text('\n'.join(lines), encoding='utf-8')
    (out_dir/'full_rows.json').write_text(json.dumps(full_rows, indent=2), encoding='utf-8')
    (out_dir/'variant_rows.json').write_text(json.dumps(var_rows, indent=2), encoding='utf-8')

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest='cmd', required=True)
    sp=sub.add_parser('compare-rid-banks')
    sp.add_argument('full_profile', type=Path)
    sp.add_argument('variant_profile', type=Path)
    sp.add_argument('out_dir', type=Path)
    ns=ap.parse_args()
    if ns.cmd=='compare-rid-banks':
        compare(ns.full_profile, ns.variant_profile, ns.out_dir)
