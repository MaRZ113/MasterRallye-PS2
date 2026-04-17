#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

RECORD_LEN = 507
RID_MARKERS = {
    '07': b'\x00\x00\x01\x07',
    '08': b'\x00\x00\x01\x08',
    '09': b'\x00\x00\x01\x09',
    '0A': b'\x00\x00\x01\x0A',
    '0B': b'\x00\x00\x01\x0B',
    '0C': b'\x00\x00\x01\x0C',
    '0D': b'\x00\x00\x01\x0D',
}

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def read_manifest(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

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
    ap = argparse.ArgumentParser(description='BX v93 rid0C sibling optional tail probe')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-sibling-tail')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v92_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-len', type=int, default=RECORD_LEN)
    p.add_argument('--after-len', type=int, default=1400)
    p.add_argument('--tail-rel', type=int, default=1178)
    p.add_argument('--tail-len', type=int, default=54)

    ns = ap.parse_args()
    if ns.cmd != 'probe-sibling-tail':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v92_root: Path = ns.v92_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_manifest(v92_root / 'sibling_manifest.csv')

    summary = []
    summary.append('BX v93 rid0C sibling optional tail probe')
    summary.append('========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'record_len: {ns.record_len}')
    summary.append(f'after_len: {ns.after_len}')
    summary.append(f'tail_rel: {ns.tail_rel}')
    summary.append(f'tail_len: {ns.tail_len}')
    summary.append('')

    rows = []

    with tng_path.open('rb') as f:
        for row in manifest:
            off = int(row['off_hex'], 16)
            body_md5 = row['body_md5']

            f.seek(off)
            rec = f.read(ns.record_len)
            f.seek(off + ns.record_len)
            after = f.read(ns.after_len)

            next_marks = nearest_next_markers(after, ns.record_len)
            next_nearest = next_marks[0] if next_marks else None

            rel0 = max(0, ns.tail_rel - ns.record_len)
            tail_gap = after[:rel0]
            tail = after[rel0: rel0 + ns.tail_len]
            tail_post = after[rel0 + ns.tail_len:]

            exact_0d = tail.startswith(RID_MARKERS['0D'])

            sdir = out_dir / row['off_hex']
            sdir.mkdir(parents=True, exist_ok=True)
            write_bytes(sdir / 'record.bin', rec)
            write_bytes(sdir / 'after.bin', after)
            write_bytes(sdir / 'tail_gap.bin', tail_gap)
            write_bytes(sdir / 'tail_candidate.bin', tail)
            write_bytes(sdir / 'tail_post.bin', tail_post)
            (sdir / 'record.hex.txt').write_text(rec.hex(), encoding='utf-8')
            (sdir / 'after.hex.txt').write_text(after.hex(), encoding='utf-8')
            (sdir / 'tail_candidate.hex.txt').write_text(tail.hex(), encoding='utf-8')

            rows.append({
                'off_hex': row['off_hex'],
                'body_md5': body_md5,
                'next_rid': next_nearest['rid'] if next_nearest else '',
                'next_delta': next_nearest['delta'] if next_nearest else '',
                'tail_candidate_is_0D': 1 if exact_0d else 0,
                'tail_head8': tail[:8].hex(),
            })

            summary.append(
                f'{row["off_hex"]}: body_md5={body_md5} '
                f'next={next_nearest["rid"]+"@"+str(next_nearest["delta"]) if next_nearest else "none"} '
                f'tail0D={exact_0d} tail_head8={tail[:8].hex()}'
            )

    with (out_dir / 'tail_probe_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['off_hex','body_md5','next_rid','next_delta','tail_candidate_is_0D','tail_head8']
        )
        w.writeheader()
        w.writerows(rows)

    grouped = defaultdict(list)
    for r in rows:
        grouped[r['body_md5']].append(r)

    summary.append('')
    summary.append('Grouped by body_md5:')
    for md5, items in grouped.items():
        summary.append(f'{md5}: count={len(items)}')
        for it in items:
            summary.append(
                f'  {it["off_hex"]}: next={it["next_rid"]}@{it["next_delta"]} tail0D={it["tail_candidate_is_0D"]}'
            )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'rows': len(rows),
        'tail_rel': ns.tail_rel,
        'tail_len': ns.tail_len,
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
