#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

RID0C_LEN = 507
TAIL_REL = 821
RID0D_LEN = 54
RID0D_MARKER = b'\x00\x00\x01\x0D'
HEAD_FAMILY_DIR = '08_0000010c423a4a02'

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def read_csv(path: Path):
    with path.open('r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def carve(src: Path, off: int, size: int) -> bytes:
    with src.open('rb') as f:
        f.seek(off)
        return f.read(size)

def main():
    ap = argparse.ArgumentParser(description='BX v86 rid0C dual-form classifier')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('classify-rid0c-forms')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v83_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-len', type=int, default=RID0C_LEN)
    p.add_argument('--tail-rel', type=int, default=TAIL_REL)
    p.add_argument('--tail-len', type=int, default=RID0D_LEN)

    ns = ap.parse_args()
    if ns.cmd != 'classify-rid0c-forms':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v83_root: Path = ns.v83_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_csv(v83_root / 'variant_context_manifest.csv')

    summary = []
    summary.append('BX v86 rid0C dual-form classifier')
    summary.append('=================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'record_len: {ns.record_len}')
    summary.append(f'tail_rel: {ns.tail_rel}')
    summary.append(f'tail_len: {ns.tail_len}')
    summary.append('')

    form_rows = []
    form_counts = Counter()
    tail_md5_counts = Counter()

    with tng_path.open('rb') as f:
        for row in manifest:
            off = int(row['off_hex'], 16)
            variant_rank = row['variant_rank']
            body_md5 = row['body_md5']

            rec = carve(tng_path, off, ns.record_len)
            after = carve(tng_path, off + ns.record_len, ns.tail_rel - ns.record_len + ns.tail_len + 64)

            gap_len = ns.tail_rel - ns.record_len
            gap = after[:gap_len]
            tail = after[gap_len:gap_len + ns.tail_len]
            post = after[gap_len + ns.tail_len:]

            has_tail = tail.startswith(RID0D_MARKER)
            form = 'tailed' if has_tail else 'standalone'
            form_counts[form] += 1

            tail_md5 = hashlib.md5(tail).hexdigest() if has_tail else ''
            if has_tail:
                tail_md5_counts[tail_md5] += 1

            hdir = out_dir / form / row['off_hex']
            hdir.mkdir(parents=True, exist_ok=True)
            write_bytes(hdir / 'rid0C_507.bin', rec)
            write_bytes(hdir / 'gap_314.bin', gap)
            write_bytes(hdir / 'tail_candidate_54.bin', tail)
            write_bytes(hdir / 'post_tail.bin', post)
            (hdir / 'rid0C_507.hex.txt').write_text(rec.hex(), encoding='utf-8')
            (hdir / 'gap_314.hex.txt').write_text(gap.hex(), encoding='utf-8')
            (hdir / 'tail_candidate_54.hex.txt').write_text(tail.hex(), encoding='utf-8')
            (hdir / 'post_tail.hex.txt').write_text(post.hex(), encoding='utf-8')

            meta = {
                'off_hex': row['off_hex'],
                'variant_rank': variant_rank,
                'body_md5': body_md5,
                'form': form,
                'has_tail': has_tail,
                'tail_head8': tail[:8].hex(),
                'tail_md5': tail_md5,
                'rid0c_sig8': rec[:8].hex(),
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            form_rows.append({
                'off_hex': row['off_hex'],
                'variant_rank': variant_rank,
                'body_md5': body_md5,
                'form': form,
                'has_tail': 1 if has_tail else 0,
                'tail_head8': tail[:8].hex(),
                'tail_md5': tail_md5,
                'rid0c_sig8': rec[:8].hex(),
            })

    with (out_dir / 'rid0c_form_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['off_hex','variant_rank','body_md5','form','has_tail','tail_head8','tail_md5','rid0c_sig8']
        )
        w.writeheader()
        w.writerows(form_rows)

    with (out_dir / 'tail_md5_counts.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['tail_md5','count'])
        w.writeheader()
        for md5, count in tail_md5_counts.most_common():
            w.writerow({'tail_md5': md5, 'count': count})

    summary.append(f'standalone_count: {form_counts["standalone"]}')
    summary.append(f'tailed_count: {form_counts["tailed"]}')
    summary.append('')
    summary.append('Tail variants:')
    for md5, count in tail_md5_counts.most_common():
        summary.append(f'  {md5} :: {count}')
    summary.append('')
    summary.append('Per-record:')
    for row in form_rows:
        summary.append(
            f'  {row["off_hex"]}: variant={row["variant_rank"]} form={row["form"]} tail_head8={row["tail_head8"]}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'standalone_count': form_counts['standalone'],
        'tailed_count': form_counts['tailed'],
        'tail_md5_counts': tail_md5_counts,
    }, indent=2, default=list), encoding='utf-8')

if __name__ == '__main__':
    main()
