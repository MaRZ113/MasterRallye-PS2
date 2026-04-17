#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

RID0C_SIG8 = bytes.fromhex('0000010c423ad203')
RID0C_LEN = 507
HEAD_LEN = 8

# Learned from v96
VARIANT_A_BODY_MD5 = '0f8e10cd03158dbd186c59f12d62bf51'   # count 3, tail @ 978
VARIANT_B_BODY_MD5 = '32db73a66cf204447041ff03b44360ca'   # count 3, tail @ 731

VARIANT_A_TAIL_DELTA = 978
VARIANT_B_TAIL_DELTA = 731
TAIL_LEN = 54

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

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def classify_body(body: bytes):
    h = md5(body)
    if h == VARIANT_A_BODY_MD5:
        return 'variant_a', VARIANT_A_TAIL_DELTA
    if h == VARIANT_B_BODY_MD5:
        return 'variant_b', VARIANT_B_TAIL_DELTA
    return 'unknown', None

def main():
    ap = argparse.ArgumentParser(description='BX v97 dual-tailed family rule emitter for rid0C 423ad203')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('emit-dual-tailed-rule')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'emit-dual-tailed-rule':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v97 dual-tailed family rule')
    summary.append('==============================')
    summary.append(f'tng_path: {tng_path}')
    summary.append('family: rid0C sig8 0000010c423ad203')
    summary.append('')

    rows = []
    companion_sig8_counts = {}

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all(mm, RID0C_SIG8)

        summary.append(f'raw_sig8_hits: {len(hits)}')
        summary.append('')

        for idx, off in enumerate(hits, 1):
            if off + RID0C_LEN + 1600 > mm.size():
                continue

            rec = bytes(mm[off:off + RID0C_LEN])
            if not rec.startswith(RID0C_SIG8):
                continue

            head = rec[:HEAD_LEN]
            body = rec[HEAD_LEN:]
            body_md5 = md5(body)
            form, tail_delta = classify_body(body)

            after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + 1600])

            tail_gap = b''
            tail = b''
            tail_post = b''
            tail_sig8 = ''
            materialized_present = False

            if tail_delta is not None:
                rel0 = tail_delta - RID0C_LEN
                tail_gap = after[:rel0]
                tail = after[rel0: rel0 + TAIL_LEN]
                tail_post = after[rel0 + TAIL_LEN:]
                materialized_present = tail.startswith(bytes.fromhex('0000010d'))
                tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''
                if tail_sig8:
                    companion_sig8_counts[tail_sig8] = companion_sig8_counts.get(tail_sig8, 0) + 1

            hdir = out_dir / f'hit_{idx:02d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)

            write_bytes(hdir / 'rid0C_507.bin', rec)
            write_bytes(hdir / 'head8.bin', head)
            write_bytes(hdir / 'body499.bin', body)
            write_bytes(hdir / 'after.bin', after)
            if tail_gap:
                write_bytes(hdir / 'tail_gap.bin', tail_gap)
            if tail:
                write_bytes(hdir / 'tail_candidate_54.bin', tail)
            if tail_post:
                write_bytes(hdir / 'tail_post.bin', tail_post)

            meta = {
                'index': idx,
                'off': off,
                'off_hex': f'0x{off:X}',
                'form': form,
                'rid0c_sig8': rec[:8].hex(),
                'body_md5': body_md5,
                'tail_delta': tail_delta,
                'tail_sig8': tail_sig8,
                'materialized_present': materialized_present,
                'head8_md5': md5(head),
                'tail_candidate_md5': md5(tail) if tail else '',
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            rows.append({
                'index': idx,
                'off_hex': f'0x{off:X}',
                'form': form,
                'body_md5': body_md5,
                'tail_delta': tail_delta if tail_delta is not None else '',
                'tail_sig8': tail_sig8,
                'materialized_present': 1 if materialized_present else 0,
                'tail_candidate_md5': md5(tail) if tail else '',
            })

            summary.append(
                f'{idx:02d}) 0x{off:X}: form={form} body_md5={body_md5} '
                f'tail_delta={tail_delta} tail_sig8={tail_sig8} materialized={materialized_present}'
            )

        mm.close()

    with (out_dir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['index','off_hex','form','body_md5','tail_delta','tail_sig8','materialized_present','tail_candidate_md5']
        )
        w.writeheader()
        w.writerows(rows)

    rule = {
        'family': {
            'rid': '0C',
            'sig8': '0000010c423ad203',
            'record_len': 507,
            'head_len': 8,
        },
        'forms': {
            'variant_a': {
                'body_md5': VARIANT_A_BODY_MD5,
                'tail_delta': VARIANT_A_TAIL_DELTA,
                'companion_rid0d_sig8': '0000010d423f4042',
                'materialized_0D': True,
            },
            'variant_b': {
                'body_md5': VARIANT_B_BODY_MD5,
                'tail_delta': VARIANT_B_TAIL_DELTA,
                'companion_rid0d_sig8': '0000010d42360299',
                'materialized_0D': True,
            },
        },
        'notes': [
            'both body variants are tailed',
            'each body variant maps to a different companion 0D subtype',
            'tail delta is family/variant specific',
        ],
        'companion_sig8_counts': companion_sig8_counts,
    }

    (out_dir / 'rid0c_423ad203_rule.json').write_text(json.dumps(rule, indent=2), encoding='utf-8')

    summary.append('')
    summary.append('Companion sig8 counts:')
    for sig8, count in companion_sig8_counts.items():
        summary.append(f'  {sig8} :: {count}')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'rule_summary.json').write_text(json.dumps(rule, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
