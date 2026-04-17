#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter
from pathlib import Path

RECORD_LEN = 507
RID0C_MARKER = b'\x00\x00\x01\x0C'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def find_all_mm(mm: mmap.mmap, needle: bytes):
    out=[]; start=0
    while True:
        i=mm.find(needle,start)
        if i==-1: break
        out.append(i); start=i+1
    return out

def find_all(data: bytes, needle: bytes):
    out=[]; start=0
    while True:
        i=data.find(needle,start)
        if i==-1: break
        out.append(i); start=i+1
    return out

def nearest_markers(before: bytes, after: bytes, rec_len: int):
    rows=[]
    for rid, marker in RID_MARKERS.items():
        for off in find_all(before, marker):
            rows.append({'rid': rid, 'delta': off - len(before)})
        for off in find_all(after, marker):
            rows.append({'rid': rid, 'delta': rec_len + off})
    rows.sort(key=lambda r:r['delta'])
    prev_rows=[r for r in rows if r['delta'] < 0]
    next_rows=[r for r in rows if r['delta'] > 0]
    return prev_rows[-1] if prev_rows else None, next_rows[0] if next_rows else None

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def main():
    ap=argparse.ArgumentParser(description='BX v129 dominant split bucket miner')
    sub=ap.add_subparsers(dest='cmd', required=True)

    p=sub.add_parser('split-dominant-bucket')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--sig7', type=str, default='0000010c425425')
    p.add_argument('--prev', type=str, default='0B@-328')
    p.add_argument('--next', type=str, default='none')
    p.add_argument('--before', type=int, default=512)
    p.add_argument('--after', type=int, default=1400)
    p.add_argument('--body-prefix-bytes', type=int, default=2)
    p.add_argument('--dominant-min-count', type=int, default=2)

    ns=ap.parse_args()
    if ns.cmd != 'split-dominant-bucket':
        raise SystemExit(1)

    out_dir=Path(ns.out_dir); out_dir.mkdir(parents=True, exist_ok=True)

    rows=[]
    branch_counts=Counter()
    sig8_counts=Counter()
    body_prefix_counts=Counter()
    body_md5_counts=Counter()

    with Path(ns.tng_path).open('rb') as f:
        mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
        hits=find_all_mm(mm, RID0C_MARKER)
        for off in hits:
            if off + RECORD_LEN > mm.size(): continue
            rec=bytes(mm[off:off+RECORD_LEN])
            sig8=rec[:8].hex()
            if not sig8.startswith(ns.sig7): continue

            body=rec[8:]
            body_md5=md5(body)
            body_prefix=body[:ns.body_prefix_bytes].hex()

            before_start=max(0, off-ns.before)
            before=bytes(mm[before_start:off]); after=bytes(mm[off+RECORD_LEN: off+RECORD_LEN+ns.after])
            prev_nearest,next_nearest=nearest_markers(before,after,RECORD_LEN)
            prev_key=f'{prev_nearest["rid"]}@{prev_nearest["delta"]}' if prev_nearest else 'none'
            next_key=f'{next_nearest["rid"]}@{next_nearest["delta"]}' if next_nearest else 'none'
            if prev_key != ns.prev or next_key != ns.next:
                continue

            branch=f'{sig8} | {body_prefix}'
            rows.append({
                'off_hex': f'0x{off:X}',
                'sig8': sig8,
                'body_md5': body_md5,
                'body_prefix': body_prefix,
                'branch_key': branch,
            })
            branch_counts[branch]+=1
            sig8_counts[sig8]+=1
            body_prefix_counts[body_prefix]+=1
            body_md5_counts[body_md5]+=1
        mm.close()

    stable=[]; unstable=[]
    for branch, count in branch_counts.most_common():
        sig8, body_prefix = [x.strip() for x in branch.split('|')]
        row={
            'branch_key': branch,
            'count': count,
            'sig8': sig8,
            'body_prefix': body_prefix,
            'status': 'stable' if count >= ns.dominant_min_count else 'unstable'
        }
        if count >= ns.dominant_min_count: stable.append(row)
        else: unstable.append(row)

    with (out_dir/'bucket_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fieldnames=['off_hex','sig8','body_md5','body_prefix','branch_key'])
        w.writeheader(); w.writerows(rows)

    with (out_dir/'stable_branches.csv').open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fieldnames=['branch_key','count','sig8','body_prefix','status'])
        w.writeheader(); w.writerows(stable)

    with (out_dir/'unstable_branches.csv').open('w', encoding='utf-8', newline='') as f:
        w=csv.DictWriter(f, fieldnames=['branch_key','count','sig8','body_prefix','status'])
        w.writeheader(); w.writerows(unstable)

    proposed_rules=[]
    for row in stable:
        proposed_rules.append({
            'name': f'dominant_prev328_{row["sig8"][-2:]}_{row["body_prefix"]}',
            'sig7': ns.sig7,
            'prev': ns.prev,
            'next': ns.next,
            'member': {
                row['sig8']: {'body_prefix': row['body_prefix']}
            },
            'count': row['count'],
        })
    (out_dir/'proposed_rules.json').write_text(json.dumps(proposed_rules, indent=2), encoding='utf-8')

    sample_root=out_dir/'samples'
    sample_root.mkdir(exist_ok=True)
    with Path(ns.tng_path).open('rb') as f:
        for idx, row in enumerate(stable[:10], 1):
            sdir=sample_root/f'{idx:02d}_{row["sig8"]}_{row["body_prefix"]}'
            sdir.mkdir(parents=True, exist_ok=True)
            hits=[r for r in rows if r['sig8']==row['sig8'] and r['body_prefix']==row['body_prefix']][:3]
            for hidx, hit in enumerate(hits, 1):
                off=int(hit['off_hex'],16)
                f.seek(off)
                rec=f.read(RECORD_LEN)
                write_bytes(sdir/f'sample_{hidx:02d}_{hit["off_hex"]}.bin', rec)

    summary=[]
    summary.append('BX v129 dominant split bucket miner')
    summary.append('=================================')
    summary.append(f'target_bucket: {ns.prev} || {ns.next}')
    summary.append(f'sig7: {ns.sig7}')
    summary.append(f'matched_hits: {len(rows)}')
    summary.append(f'unique_sig8: {len(sig8_counts)}')
    summary.append(f'unique_body_prefix: {len(body_prefix_counts)}')
    summary.append(f'unique_body_md5: {len(body_md5_counts)}')
    summary.append(f'stable_branches: {len(stable)}')
    summary.append(f'unstable_branches: {len(unstable)}')
    summary.append('')
    summary.append('sig8 counts:')
    for k,v in sig8_counts.most_common():
        summary.append(f'  {k} :: {v}')
    summary.append('')
    summary.append('Stable branches:')
    for row in stable:
        summary.append(f'  {row["branch_key"]} :: {row["count"]}')
    summary.append('')
    summary.append('Unstable branches:')
    for row in unstable:
        summary.append(f'  {row["branch_key"]} :: {row["count"]}')

    (out_dir/'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir/'meta.json').write_text(json.dumps({
        'matched_hits': len(rows),
        'stable_branches': len(stable),
        'unstable_branches': len(unstable),
    }, indent=2), encoding='utf-8')

if __name__=='__main__':
    main()
