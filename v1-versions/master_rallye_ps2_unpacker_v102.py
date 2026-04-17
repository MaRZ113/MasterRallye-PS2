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
RID0D_MARKER = b'\x00\x00\x01\x0D'

# Unified known rid0C framework after v101
REGISTRY = {
    # family-specific optional companion class
    '0000010c423a4a02': {
        'class': 'optional_companion',
        'head_len': 68,
        'forms': {
            'c0e70b5dfa4117b3c5d3d71e29053fd1': {
                'form': 'standalone',
                'tail_delta': None,
                'companion_sig8': None,
            },
            '57021a2e1879924ce8eb23eb6ea1d261': {
                'form': 'tailed',
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
                'form': 'standalone',
                'tail_delta': None,
                'companion_sig8': None,
            },
            '060cfade69be9adffb220b5b43235071': {
                'form': 'tailed',
                'tail_delta': 1178,
                'companion_sig8': '0000010d423f39c9',
            },
        },
    },

    # family-specific dual-tailed class
    '0000010c423ad203': {
        'class': 'dual_tailed',
        'head_len': 8,
        'forms': {
            '0f8e10cd03158dbd186c59f12d62bf51': {
                'form': 'variant_a',
                'tail_delta': 978,
                'companion_sig8': '0000010d423f4042',
            },
            '32db73a66cf204447041ff03b44360ca': {
                'form': 'variant_b',
                'tail_delta': 731,
                'companion_sig8': '0000010d42360299',
            },
        },
    },

    # optional exact-head class
    '0000010c423ac340': {
        'class': 'optional_exact_head',
        'head_len': 507,
        'tail_delta': 755,
        'latent_off': 4,
    },
    '0000010c423a8945': {
        'class': 'optional_exact_head',
        'head_len': 507,
        'tail_delta': 830,
        'latent_off': 10,
    },
    '0000010c423a4864': {
        'class': 'optional_exact_head',
        'head_len': 507,
        'tail_delta': 920,
        'latent_off': 4,
    },

    # fixed-tail exact-head class
    '0000010c423a40ae': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 781},
    '0000010c423a0063': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 695},
    '0000010c423ad082': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 874},
    '0000010c423ac0c0': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 795},
    '0000010c423ac02c': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 1278},
    '0000010c423a4b1a': {'class': 'fixed_tail_exact_head', 'head_len': 507, 'tail_delta': 771},
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
    ap = argparse.ArgumentParser(description='BX v102 unified rid0C meta-registry extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-rid0c-meta')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--after-len', type=int, default=1600)

    ns = ap.parse_args()
    if ns.cmd != 'extract-rid0c-meta':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v102 unified rid0C meta-registry extractor')
    summary.append('============================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'known_families: {len(REGISTRY)}')
    summary.append('')

    all_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for sig8_hex, rule in REGISTRY.items():
            sig8 = bytes.fromhex(sig8_hex)
            hits = find_all(mm, sig8)
            fam_dir = out_dir / sig8_hex
            fam_dir.mkdir(parents=True, exist_ok=True)

            fam_rows = []
            for idx, off in enumerate(hits, 1):
                if off + RID0C_LEN + ns.after_len > mm.size():
                    continue

                rec = bytes(mm[off:off + RID0C_LEN])
                if not rec.startswith(sig8):
                    continue

                body = rec[rule['head_len']:] if rule['head_len'] < RID0C_LEN else b''
                body_md5 = md5(body) if body else ''
                after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ns.after_len])

                form = 'exact_head'
                expected_tail_delta = rule.get('tail_delta')
                expected_companion_sig8 = ''
                latent_off = rule.get('latent_off', '')

                if rule['class'] in ('optional_companion', 'dual_tailed'):
                    form_info = rule['forms'].get(body_md5)
                    if form_info:
                        form = form_info['form']
                        expected_tail_delta = form_info['tail_delta']
                        expected_companion_sig8 = form_info['companion_sig8'] or ''
                    else:
                        form = 'unknown_body'

                tail = b''
                tail_present = False
                observed_tail_sig8 = ''
                if expected_tail_delta is not None:
                    rel0 = max(0, expected_tail_delta - RID0C_LEN)
                    tail = after[rel0:rel0 + TAIL_LEN]
                    tail_present = tail.startswith(RID0D_MARKER)
                    observed_tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

                hdir = fam_dir / f'hit_{idx:02d}_0x{off:X}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'rid0C_507.bin', rec)
                write_bytes(hdir / 'after.bin', after)
                if tail:
                    write_bytes(hdir / 'tail_candidate_54.bin', tail)

                meta = {
                    'index': idx,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'family_class': rule['class'],
                    'head_len': rule['head_len'],
                    'form': form,
                    'body_md5': body_md5,
                    'expected_tail_delta': expected_tail_delta,
                    'latent_off': latent_off,
                    'expected_companion_sig8': expected_companion_sig8,
                    'tail_present': tail_present,
                    'observed_tail_sig8': observed_tail_sig8,
                }
                (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

                row = {
                    'index': idx,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'family_class': rule['class'],
                    'head_len': rule['head_len'],
                    'form': form,
                    'body_md5': body_md5,
                    'expected_tail_delta': expected_tail_delta if expected_tail_delta is not None else '',
                    'latent_off': latent_off,
                    'expected_companion_sig8': expected_companion_sig8,
                    'tail_present': 1 if tail_present else 0,
                    'observed_tail_sig8': observed_tail_sig8,
                    'match_expected_companion': 1 if (not expected_companion_sig8 or expected_companion_sig8 == observed_tail_sig8) else 0,
                }
                fam_rows.append(row)
                all_rows.append(row)

            with (fam_dir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
                fieldnames = ['index','off_hex','family_sig8','family_class','head_len','form','body_md5','expected_tail_delta','latent_off','expected_companion_sig8','tail_present','observed_tail_sig8','match_expected_companion']
                w = csv.DictWriter(f_csv, fieldnames=fieldnames)
                w.writeheader()
                w.writerows(fam_rows)

            form_counts = {}
            for r in fam_rows:
                form_counts[r['form']] = form_counts.get(r['form'], 0) + 1
            mismatches = sum(1 for r in fam_rows if r['tail_present'] and r['expected_companion_sig8'] and not r['match_expected_companion'])
            unknown = sum(1 for r in fam_rows if r['form'] == 'unknown_body')
            summary.append(f'[{sig8_hex}] class={rule["class"]} extracted={len(fam_rows)} forms={form_counts} unknown={unknown} mismatches={mismatches}')
            summary.append('')

        mm.close()

    with (out_dir / 'meta_framework_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
        fieldnames = ['index','off_hex','family_sig8','family_class','head_len','form','body_md5','expected_tail_delta','latent_off','expected_companion_sig8','tail_present','observed_tail_sig8','match_expected_companion']
        w = csv.DictWriter(f_csv, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_rows)

    (out_dir / 'meta_registry.json').write_text(json.dumps(REGISTRY, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
