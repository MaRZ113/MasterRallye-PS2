#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

RID0C_LEN = 507
TAIL_LEN = 54

FAMILY_REGISTRY = {
    # optional-companion class
    '0000010c423a4a02': {
        'class': 'optional_companion',
        'head_len': 68,
        'forms': {
            'c0e70b5dfa4117b3c5d3d71e29053fd1': {
                'name': 'standalone',
                'tail_delta': None,
                'companion_sig8': None,
            },
            '57021a2e1879924ce8eb23eb6ea1d261': {
                'name': 'tailed',
                'tail_delta': 821,
                'companion_sig8': '0000010d423f4fc8',
            },
        },
    },
    '0000010c423a0868': {
        'class': 'optional_companion',
        'head_len': 34,
        'forms': {
            'a00d36eb1a3284b277512914f46d56ca': {
                'name': 'standalone',
                'tail_delta': None,
                'companion_sig8': None,
            },
            '060cfade69be9adffb220b5b43235071': {
                'name': 'tailed',
                'tail_delta': 1178,
                'companion_sig8': '0000010d423f39c9',
            },
        },
    },
    # dual-tailed class
    '0000010c423ad203': {
        'class': 'dual_tailed',
        'head_len': 8,
        'forms': {
            '0f8e10cd03158dbd186c59f12d62bf51': {
                'name': 'variant_a',
                'tail_delta': 978,
                'companion_sig8': '0000010d423f4042',
            },
            '32db73a66cf204447041ff03b44360ca': {
                'name': 'variant_b',
                'tail_delta': 731,
                'companion_sig8': '0000010d42360299',
            },
        },
    },
}

def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

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

def main():
    ap = argparse.ArgumentParser(description='BX v98 rid0C framework extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-rid0c-framework')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--after-len', type=int, default=1600)

    ns = ap.parse_args()
    if ns.cmd != 'extract-rid0c-framework':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v98 rid0C framework extractor')
    summary.append('================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'known_families: {len(FAMILY_REGISTRY)}')
    summary.append('')

    all_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for sig8_hex, family in FAMILY_REGISTRY.items():
            sig8 = bytes.fromhex(sig8_hex)
            fam_dir = out_dir / sig8_hex
            fam_dir.mkdir(parents=True, exist_ok=True)

            hits = find_all(mm, sig8)
            summary.append(f'[{sig8_hex}] class={family["class"]} raw_hits={len(hits)}')

            fam_rows = []
            for idx, off in enumerate(hits, 1):
                if off + RID0C_LEN + ns.after_len > mm.size():
                    continue
                rec = bytes(mm[off:off + RID0C_LEN])
                if not rec.startswith(sig8):
                    continue

                head = rec[:family['head_len']]
                body = rec[family['head_len']:]
                body_md5 = md5(body)

                form_info = family['forms'].get(body_md5)
                form_name = form_info['name'] if form_info else 'unknown'
                tail_delta = form_info['tail_delta'] if form_info else None
                companion_sig8 = form_info['companion_sig8'] if form_info else None

                after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ns.after_len])

                tail = b''
                tail_present = False
                tail_sig8 = ''
                tail_gap = b''
                tail_post = b''
                if tail_delta is not None:
                    rel0 = max(0, tail_delta - RID0C_LEN)
                    tail_gap = after[:rel0]
                    tail = after[rel0:rel0 + TAIL_LEN]
                    tail_post = after[rel0 + TAIL_LEN:]
                    tail_present = tail.startswith(bytes.fromhex('0000010d'))
                    tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

                hdir = fam_dir / f'hit_{idx:02d}_0x{off:X}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'rid0C_507.bin', rec)
                write_bytes(hdir / 'head.bin', head)
                write_bytes(hdir / 'body.bin', body)
                write_bytes(hdir / 'after.bin', after)
                if tail_delta is not None:
                    write_bytes(hdir / 'tail_gap.bin', tail_gap)
                    write_bytes(hdir / 'tail_candidate_54.bin', tail)
                    write_bytes(hdir / 'tail_post.bin', tail_post)

                meta = {
                    'index': idx,
                    'off': off,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'family_class': family['class'],
                    'head_len': family['head_len'],
                    'form': form_name,
                    'body_md5': body_md5,
                    'tail_delta': tail_delta,
                    'expected_companion_sig8': companion_sig8,
                    'tail_present': tail_present,
                    'observed_tail_sig8': tail_sig8,
                }
                (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

                fam_rows.append({
                    'index': idx,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'family_class': family['class'],
                    'form': form_name,
                    'body_md5': body_md5,
                    'tail_delta': tail_delta if tail_delta is not None else '',
                    'expected_companion_sig8': companion_sig8 if companion_sig8 else '',
                    'tail_present': 1 if tail_present else 0,
                    'observed_tail_sig8': tail_sig8,
                })
                all_rows.append(fam_rows[-1])

            with (fam_dir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(
                    f_csv,
                    fieldnames=['index','off_hex','family_sig8','family_class','form','body_md5','tail_delta','expected_companion_sig8','tail_present','observed_tail_sig8']
                )
                w.writeheader()
                w.writerows(fam_rows)

            form_counts = {}
            for r in fam_rows:
                form_counts[r['form']] = form_counts.get(r['form'], 0) + 1
            summary.append(f'  extracted={len(fam_rows)} forms={form_counts}')
            summary.append('')

        mm.close()

    with (out_dir / 'framework_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['index','off_hex','family_sig8','family_class','form','body_md5','tail_delta','expected_companion_sig8','tail_present','observed_tail_sig8']
        )
        w.writeheader()
        w.writerows(all_rows)

    (out_dir / 'registry.json').write_text(json.dumps(FAMILY_REGISTRY, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
