#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

REC_RE = re.compile(b'\x00\x00\x01(.)', re.DOTALL)

def find_records(data: bytes):
    hits = []
    for m in REC_RE.finditer(data):
        rid = data[m.start()+3]
        hits.append((m.start(), rid))
    return hits

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def sanitize(s: str) -> str:
    bad='<>:"/\\|?*'
    out=''.join('_' if c in bad else c for c in s)
    return out.strip(' .') or 'unnamed'

def main():
    ap = argparse.ArgumentParser(description='BX v42 nested record splitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('split-candidate')
    p.add_argument('candidate_dir', type=Path, help='one v41 candidate directory')
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'split-candidate':
        raise SystemExit(1)

    cand_dir: Path = ns.candidate_dir
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    cand = (cand_dir / 'candidate.bin').read_bytes()
    hits = find_records(cand)

    summary = []
    summary.append('BX v42 nested record split')
    summary.append('=========================')
    summary.append(f'candidate_dir: {cand_dir}')
    summary.append(f'candidate_len: {len(cand)}')
    summary.append(f'record_markers: {len(hits)}')
    summary.append('')

    rows = []

    # pre-record head if candidate starts before first record marker
    if hits and hits[0][0] > 0:
        pre = cand[:hits[0][0]]
        write_bytes(out_dir / 'pre_record_head.bin', pre)
        (out_dir / 'pre_record_head.hex.txt').write_text(pre.hex(), encoding='utf-8')
        rows.append({'index': 0, 'rid': '', 'off': 0, 'len': len(pre), 'kind': 'pre_record_head', 'file': 'pre_record_head.bin'})
        summary.append(f'pre_record_head: len={len(pre)}')

    for i, (off, rid) in enumerate(hits):
        end = hits[i+1][0] if i+1 < len(hits) else len(cand)
        blob = cand[off:end]
        rid_hex = f'{rid:02X}'
        name = f'record_{i+1:02d}_rid_{rid_hex}.bin'
        write_bytes(out_dir / name, blob)
        (out_dir / (name + '.hex.txt')).write_text(blob.hex(), encoding='utf-8')
        rows.append({'index': i+1, 'rid': rid_hex, 'off': off, 'len': len(blob), 'kind': 'record', 'file': name})
        summary.append(f'{i+1:02d}) off={off} rid=0x{rid_hex} len={len(blob)}')

    with (out_dir / 'record_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','rid','off','len','kind','file'])
        w.writeheader()
        w.writerows(rows)

    meta = {
        'candidate_len': len(cand),
        'record_count': len(hits),
        'records': [{'off': off, 'rid': rid} for off, rid in hits],
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
