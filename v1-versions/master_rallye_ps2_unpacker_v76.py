#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from collections import Counter, defaultdict
from pathlib import Path

RECORD_LEN = 507

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def find_all(mm: mmap.mmap, needle: bytes):
    out = []
    start = 0
    while True:
        i = mm.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out

def main():
    ap = argparse.ArgumentParser(description='BX v76 rid0C head-family body variant miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-rid0c-head-family')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v75_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-len', type=int, default=RECORD_LEN)
    p.add_argument('--max-export-per-variant', type=int, default=3)

    ns = ap.parse_args()
    if ns.cmd != 'mine-rid0c-head-family':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v75_root: Path = ns.v75_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    head = read_bytes(v75_root / 'shared_head.bin')
    body_start = len(head)

    summary = []
    summary.append('BX v76 rid0C head-family miner')
    summary.append('==============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'head_len: {len(head)}')
    summary.append(f'record_len: {ns.record_len}')
    summary.append('')

    body_counter = Counter()
    body_examples = defaultdict(list)
    full_counter = Counter()
    full_examples = defaultdict(list)

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all(mm, head)

        valid_hits = []
        for off in hits:
            if off + ns.record_len > mm.size():
                continue
            rec = bytes(mm[off:off+ns.record_len])
            # keep only exact head-family members starting with the full 68-byte head
            if not rec.startswith(head):
                continue
            valid_hits.append((off, rec))

            body = rec[body_start:]
            body_md5 = hashlib.md5(body).hexdigest()
            full_md5 = hashlib.md5(rec).hexdigest()
            body_counter[body_md5] += 1
            full_counter[full_md5] += 1

            if len(body_examples[body_md5]) < ns.max_export_per_variant:
                body_examples[body_md5].append((off, rec))
            if len(full_examples[full_md5]) < ns.max_export_per_variant:
                full_examples[full_md5].append((off, rec))

        mm.close()

    summary.append(f'raw_head_hits: {len(hits)}')
    summary.append(f'valid_records: {len(valid_hits)}')
    summary.append(f'unique_full_records: {len(full_counter)}')
    summary.append(f'unique_body_variants: {len(body_counter)}')
    summary.append('')

    # write global hit list
    with (out_dir / 'valid_hits.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['index','off','off_hex'])
        w.writeheader()
        for idx, (off, _) in enumerate(valid_hits, 1):
            w.writerow({'index': idx, 'off': off, 'off_hex': f'0x{off:X}'})

    # body variants
    with (out_dir / 'body_variant_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','body_md5','count'])
        w.writeheader()
        for rank, (md5, count) in enumerate(body_counter.most_common(), 1):
            w.writerow({'rank': rank, 'body_md5': md5, 'count': count})

    with (out_dir / 'full_record_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['rank','record_md5','count'])
        w.writeheader()
        for rank, (md5, count) in enumerate(full_counter.most_common(), 1):
            w.writerow({'rank': rank, 'record_md5': md5, 'count': count})

    var_root = out_dir / 'body_variants'
    var_root.mkdir(exist_ok=True)

    rep_rows = []
    for rank, (md5, count) in enumerate(body_counter.most_common(12), 1):
        vdir = var_root / f'{rank:02d}_{md5}'
        vdir.mkdir(parents=True, exist_ok=True)

        examples = body_examples[md5]
        for idx, (off, rec) in enumerate(examples, 1):
            body = rec[body_start:]
            write_bytes(vdir / f'sample_{idx:02d}_0x{off:X}.bin', body)
            (vdir / f'sample_{idx:02d}_0x{off:X}.hex.txt').write_text(body.hex(), encoding='utf-8')
            write_bytes(vdir / f'sample_{idx:02d}_0x{off:X}_full.bin', rec)
            rep_rows.append({
                'variant_rank': rank,
                'body_md5': md5,
                'count': count,
                'off_hex': f'0x{off:X}',
                'body_head16': body[:16].hex(),
            })

        summary.append(f'body_variant {rank:02d}: count={count} md5={md5}')
        if examples:
            body0 = examples[0][1][body_start:]
            summary.append(f'  body_head16={body0[:16].hex()}')

    with (out_dir / 'representative_body_variants.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['variant_rank','body_md5','count','off_hex','body_head16'])
        w.writeheader()
        w.writerows(rep_rows)

    meta = {
        'head_len': len(head),
        'record_len': ns.record_len,
        'raw_head_hits': len(hits),
        'valid_records': len(valid_hits),
        'unique_full_records': len(full_counter),
        'unique_body_variants': len(body_counter),
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
