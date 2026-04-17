#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

REC_RE = re.compile(b'\x00\x00\x01(.)', re.DOTALL)

DEFAULT_TARGETS = [
    '03_branch_BXI__hit_025_0x3C10E18E_bx_chunk_2',
    '04_branch_BXI__hit_019_0x384BBA83_bx_chunk_2',
    '05_branch_BXI1_hit_022_0x3B1D22A1_bx_chunk_3',
]

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_records(data: bytes) -> List[Tuple[int,int]]:
    hits = []
    for m in REC_RE.finditer(data):
        rid = data[m.start()+3]
        hits.append((m.start(), rid))
    return hits

def split_candidate_bytes(data: bytes) -> Dict[str, object]:
    hits = find_records(data)
    out = {'pre_head': b'', 'records': []}
    if hits and hits[0][0] > 0:
        out['pre_head'] = data[:hits[0][0]]
    for i, (off, rid) in enumerate(hits):
        end = hits[i+1][0] if i+1 < len(hits) else len(data)
        out['records'].append({
            'rid': rid,
            'off': off,
            'len': end - off,
            'data': data[off:end],
        })
    return out

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

def family_from_name(name: str) -> str:
    if 'branch_BXI1' in name:
        return 'BXI1'
    if 'branch_BXI_' in name:
        return 'BXI_'
    return 'unknown'

def main():
    ap = argparse.ArgumentParser(description='BX v43 nested subrecord comparer')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('compare-nested')
    p.add_argument('v41_root', type=Path, help='v41_candidates root')
    p.add_argument('out_dir', type=Path)
    p.add_argument('--targets', nargs='*', default=DEFAULT_TARGETS)

    ns = ap.parse_args()
    if ns.cmd != 'compare-nested':
        raise SystemExit(1)

    root: Path = ns.v41_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # gather selected candidates
    candidates = []
    for t in ns.targets:
        cdir = root / t
        cand = cdir / 'candidate.bin'
        if not cand.exists():
            continue
        data = read_bytes(cand)
        split = split_candidate_bytes(data)
        candidates.append({
            'name': t,
            'family': family_from_name(t),
            'path': cdir,
            'data': data,
            'split': split,
        })

    summary = []
    summary.append('BX v43 nested subrecord compare')
    summary.append('===============================')
    summary.append(f'v41_root: {root}')
    summary.append(f'targets_loaded: {len(candidates)}')
    summary.append('')

    # write per-candidate split outputs
    for c in candidates:
        c_out = out_dir / c['name']
        c_out.mkdir(parents=True, exist_ok=True)
        pre = c['split']['pre_head']
        if pre:
            write_bytes(c_out / 'pre_record_head.bin', pre)
            (c_out / 'pre_record_head.hex.txt').write_text(pre.hex(), encoding='utf-8')
        rows = []
        for i, rec in enumerate(c['split']['records'], 1):
            rid_hex = f'{rec["rid"]:02X}'
            name = f'record_{i:02d}_rid_{rid_hex}.bin'
            write_bytes(c_out / name, rec['data'])
            (c_out / (name + '.hex.txt')).write_text(rec['data'].hex(), encoding='utf-8')
            rows.append({'index': i, 'rid': rid_hex, 'off': rec['off'], 'len': rec['len'], 'file': name})
        with (c_out / 'record_manifest.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['index','rid','off','len','file'])
            w.writeheader()
            w.writerows(rows)
        summary.append(f'{c["name"]}: family={c["family"]} pre={len(pre)} records={[(hex(r["rid"]), r["len"]) for r in c["split"]["records"]]}')

    summary.append('')

    # group by rid across candidates
    rid_bank = {}
    for c in candidates:
        for rec in c['split']['records']:
            rid_bank.setdefault(rec['rid'], []).append({
                'candidate': c['name'],
                'family': c['family'],
                'len': rec['len'],
                'data': rec['data'],
            })

    compare_rows = []
    rid_bank_dir = out_dir / 'rid_banks'
    rid_bank_dir.mkdir(exist_ok=True)

    for rid, items in sorted(rid_bank.items()):
        rid_hex = f'{rid:02X}'
        rdir = rid_bank_dir / f'rid_{rid_hex}'
        rdir.mkdir(parents=True, exist_ok=True)

        # dump items
        for idx, item in enumerate(items, 1):
            safe_name = f'{idx:02d}_{item["family"]}_{item["candidate"]}.bin'.replace('\\','_').replace('/','_')
            write_bytes(rdir / safe_name, item['data'])

        # pairwise comparisons
        for i in range(len(items)):
            for j in range(i+1, len(items)):
                a = items[i]
                b = items[j]
                cp = common_prefix_len(a['data'], b['data'])
                cs = common_suffix_len(a['data'], b['data'])
                compare_rows.append({
                    'rid': rid_hex,
                    'a_family': a['family'],
                    'b_family': b['family'],
                    'a_candidate': a['candidate'],
                    'b_candidate': b['candidate'],
                    'a_len': len(a['data']),
                    'b_len': len(b['data']),
                    'common_prefix': cp,
                    'common_suffix': cs,
                })

    with (out_dir / 'subrecord_compare.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['rid','a_family','b_family','a_candidate','b_candidate','a_len','b_len','common_prefix','common_suffix']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(compare_rows)

    # brief interpretation
    summary.append('Per-RID strongest similarities:')
    for rid_hex in sorted({r['rid'] for r in compare_rows}):
        rows = [r for r in compare_rows if r['rid'] == rid_hex]
        if not rows:
            continue
        rows.sort(key=lambda r: (r['common_prefix'], r['common_suffix']), reverse=True)
        best = rows[0]
        summary.append(
            f'rid {rid_hex}: best_prefix={best["common_prefix"]} best_suffix={best["common_suffix"]} '
            f'{best["a_family"]}:{best["a_candidate"]} vs {best["b_family"]}:{best["b_candidate"]}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
