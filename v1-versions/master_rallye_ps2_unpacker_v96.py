#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507
DEFAULT_FAMILY_DIR = '01_0000010c423ad203'
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_all_mm(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def find_all(data: bytes, needle: bytes):
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def nearest_next_markers(after: bytes, rec_len: int):
    rows = []
    for rid, marker in RID_MARKERS.items():
        for off in find_all(after, marker):
            rows.append({'rid': rid, 'delta': rec_len + off})
    rows.sort(key=lambda r: r['delta'])
    return rows

def main():
    ap = argparse.ArgumentParser(description='BX v96 rid0C dual-tailed family probe')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-dual-tailed-family')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v74_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--family-dir', type=str, default=DEFAULT_FAMILY_DIR)
    p.add_argument('--record-len', type=int, default=RECORD_LEN)
    p.add_argument('--after-len', type=int, default=1600)
    p.add_argument('--tail-len', type=int, default=54)

    ns = ap.parse_args()
    if ns.cmd != 'probe-dual-tailed-family':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v74_root: Path = ns.v74_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fam_dir = v74_root / 'sig8_families' / ns.family_dir
    if not fam_dir.exists():
        raise SystemExit(f'Family dir not found: {fam_dir}')

    shared_head = read_bytes(fam_dir / 'shared_head.bin')
    head_len = len(shared_head)
    family_meta = json.loads((fam_dir / 'family_meta.json').read_text(encoding='utf-8'))

    summary = []
    summary.append('BX v96 rid0C dual-tailed family probe')
    summary.append('=====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'family_dir: {ns.family_dir}')
    summary.append(f'sig8: {family_meta.get("sig8","")}')
    summary.append(f'shared_head_len: {head_len}')
    summary.append('')

    hits_by_body = defaultdict(list)
    next_by_body = defaultdict(Counter)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        raw_hits = find_all_mm(mm, shared_head)
        valid = []
        for off in raw_hits:
            if off + ns.record_len > mm.size():
                continue
            rec = bytes(mm[off:off+ns.record_len])
            if not rec.startswith(shared_head):
                continue
            body = rec[head_len:]
            body_md5 = hashlib.md5(body).hexdigest()
            after = bytes(mm[off + ns.record_len: off + ns.record_len + ns.after_len])
            next_marks = nearest_next_markers(after, ns.record_len)
            next_nearest = next_marks[0] if next_marks else None
            hits_by_body[body_md5].append({
                'off': off,
                'rec': rec,
                'after': after,
                'next_nearest': next_nearest,
            })
            if next_nearest:
                next_by_body[body_md5][(next_nearest['rid'], next_nearest['delta'])] += 1
            else:
                next_by_body[body_md5][('none','')] += 1
            valid.append(off)
        mm.close()

    summary.append(f'raw_hits: {len(raw_hits)}')
    summary.append(f'valid_hits: {len(valid)}')
    summary.append(f'unique_body_md5: {len(hits_by_body)}')
    summary.append('')

    manifest_rows = []

    for rank, (body_md5, items) in enumerate(sorted(hits_by_body.items(), key=lambda kv: (-len(kv[1]), kv[0])), 1):
        vdir = out_dir / f'variant_{rank:02d}_{body_md5}'
        vdir.mkdir(parents=True, exist_ok=True)

        top_next = next_by_body[body_md5].most_common(1)[0]
        (rid, delta), count = top_next
        summary.append(f'variant {rank:02d}: body_md5={body_md5} count={len(items)} top_next={rid}@{delta}::{count}')

        with (vdir / 'variant_meta.json').open('w', encoding='utf-8') as f:
            json.dump({
                'body_md5': body_md5,
                'count': len(items),
                'top_next': {'rid': rid, 'delta': delta, 'count': count},
            }, f, indent=2)

        for idx, item in enumerate(items, 1):
            off = item['off']
            rec = item['rec']
            after = item['after']
            next_nearest = item['next_nearest']

            sdir = vdir / f'sample_{idx:02d}_0x{off:X}'
            sdir.mkdir(parents=True, exist_ok=True)

            write_bytes(sdir / 'record.bin', rec)
            write_bytes(sdir / 'after.bin', after)
            (sdir / 'record.hex.txt').write_text(rec.hex(), encoding='utf-8')

            tail_gap = b''
            tail = b''
            tail_post = b''
            exact_0d = False
            if rid == '0D' and isinstance(delta, int):
                rel0 = max(0, delta - ns.record_len)
                tail_gap = after[:rel0]
                tail = after[rel0: rel0 + ns.tail_len]
                tail_post = after[rel0 + ns.tail_len:]
                exact_0d = tail.startswith(RID_MARKERS['0D'])

                write_bytes(sdir / 'tail_gap.bin', tail_gap)
                write_bytes(sdir / 'tail_candidate.bin', tail)
                write_bytes(sdir / 'tail_post.bin', tail_post)
                (sdir / 'tail_candidate.hex.txt').write_text(tail.hex(), encoding='utf-8')

            manifest_rows.append({
                'variant_rank': rank,
                'body_md5': body_md5,
                'off_hex': f'0x{off:X}',
                'next_rid': next_nearest['rid'] if next_nearest else '',
                'next_delta': next_nearest['delta'] if next_nearest else '',
                'tail_candidate_is_0D': 1 if exact_0d else 0,
                'tail_head8': tail[:8].hex() if tail else '',
            })

    with (out_dir / 'dual_tailed_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['variant_rank','body_md5','off_hex','next_rid','next_delta','tail_candidate_is_0D','tail_head8']
        )
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'family_dir': ns.family_dir,
        'raw_hits': len(raw_hits),
        'valid_hits': len(valid),
        'unique_body_md5': len(hits_by_body),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
