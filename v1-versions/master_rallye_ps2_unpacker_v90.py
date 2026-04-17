#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

RID0C_LEN = 507

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
    ap = argparse.ArgumentParser(description='BX v90 first family-specific unpacker rule emitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('emit-rid0c-rule')
    p.add_argument('tng_path', type=Path)
    p.add_argument('v83_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--record-len', type=int, default=RID0C_LEN)

    ns = ap.parse_args()
    if ns.cmd != 'emit-rid0c-rule':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    v83_root: Path = ns.v83_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_csv(v83_root / 'variant_context_manifest.csv')

    summary = []
    summary.append('BX v90 first family-specific unpacker rule')
    summary.append('=========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'v83_root: {v83_root}')
    summary.append('')

    normalized_rows = []
    core_md5s = Counter()
    materialized_md5s = Counter()
    latent_md5s = Counter()

    for row in manifest:
        off = int(row['off_hex'], 16)
        variant_rank = int(row['variant_rank'])
        body_md5 = row['body_md5']

        rec = carve(tng_path, off, ns.record_len)
        after = carve(tng_path, off + ns.record_len, 432)

        # Based on v89/v88 findings:
        # standalone form -> latent companion stream starts at zone+322
        # tailed form     -> materialized 0D starts at zone+314, canonical core at zone+317
        if variant_rank == 1:
            form = 'standalone'
            wrapper = after[316:322]          # 6 bytes before latent core
            latent54 = after[322:376]         # 54 bytes beginning with 0d423f...
            core110 = after[322:432]          # full shared companion core
            materialized54 = b''
            materialized_present = False
        else:
            form = 'tailed'
            wrapper = after[313:317]          # 4 bytes before materialized core
            materialized54 = after[314:368]   # exact 0D record
            latent54 = after[317:371]         # same stream without 000001
            core110 = after[317:427]          # shared companion core
            materialized_present = materialized54.startswith(bytes.fromhex('0000010d'))

        core_md5 = hashlib.md5(core110).hexdigest()
        latent_md5 = hashlib.md5(latent54).hexdigest()
        materialized_md5 = hashlib.md5(materialized54).hexdigest() if materialized54 else ''

        core_md5s[core_md5] += 1
        latent_md5s[latent_md5] += 1
        if materialized_md5:
            materialized_md5s[materialized_md5] += 1

        hdir = out_dir / 'normalized' / row['off_hex']
        hdir.mkdir(parents=True, exist_ok=True)
        write_bytes(hdir / 'rid0C_507.bin', rec)
        write_bytes(hdir / 'wrapper.bin', wrapper)
        write_bytes(hdir / 'latent54.bin', latent54)
        write_bytes(hdir / 'core110.bin', core110)
        if materialized54:
            write_bytes(hdir / 'materialized54.bin', materialized54)

        meta = {
            'off_hex': row['off_hex'],
            'variant_rank': variant_rank,
            'body_md5': body_md5,
            'form': form,
            'rid0c_sig8': rec[:8].hex(),
            'wrapper_hex': wrapper.hex(),
            'latent54_head16': latent54[:16].hex(),
            'core110_head16': core110[:16].hex(),
            'core110_md5': core_md5,
            'latent54_md5': latent_md5,
            'materialized54_md5': materialized_md5,
            'materialized_present': materialized_present,
        }
        (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        normalized_rows.append({
            'off_hex': row['off_hex'],
            'variant_rank': variant_rank,
            'body_md5': body_md5,
            'form': form,
            'wrapper_hex': wrapper.hex(),
            'core110_md5': core_md5,
            'latent54_md5': latent_md5,
            'materialized54_md5': materialized_md5,
            'materialized_present': 1 if materialized_present else 0,
        })

    with (out_dir / 'normalized_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['off_hex','variant_rank','body_md5','form','wrapper_hex','core110_md5','latent54_md5','materialized54_md5','materialized_present']
        )
        w.writeheader()
        w.writerows(normalized_rows)

    rule = {
        'family': {
            'rid': '0C',
            'sig8': '0000010c423a4a02',
            'record_len': 507,
            'head_len': 68,
        },
        'forms': {
            'standalone': {
                'variant_rank': 1,
                'body_md5': 'c0e70b5dfa4117b3c5d3d71e29053fd1',
                'wrapper_len': 6,
                'latent54_off_in_zone': 322,
                'core110_off_in_zone': 322,
                'materialized_0D': False,
            },
            'tailed': {
                'variant_rank': 2,
                'body_md5': '57021a2e1879924ce8eb23eb6ea1d261',
                'wrapper_len': 4,
                'materialized54_off_in_zone': 314,
                'latent54_off_in_zone': 317,
                'core110_off_in_zone': 317,
                'materialized_0D': True,
                'companion_rid0d_sig8': '0000010d423f4fc8',
            },
        },
        'invariants': {
            'core110_md5_counts': dict(core_md5s),
            'latent54_md5_counts': dict(latent_md5s),
            'materialized54_md5_counts': dict(materialized_md5s),
        },
        'notes': [
            'tailed form materializes a 0D record by prepending 000001 before the same latent stream',
            'core110 is shared across both forms',
            'standalone keeps the companion stream latent, without the 000001 marker',
        ],
    }
    (out_dir / 'rid0c_423a4a02_rule.json').write_text(json.dumps(rule, indent=2), encoding='utf-8')

    summary.append('Family rule summary:')
    summary.append('  rid0C sig8 = 0000010c423a4a02')
    summary.append('  record_len = 507')
    summary.append('  head_len = 68')
    summary.append('  forms = standalone / tailed')
    summary.append('')
    summary.append('Normalized invariants:')
    for md5, count in core_md5s.items():
        summary.append(f'  core110 {md5} :: {count}')
    for md5, count in latent_md5s.items():
        summary.append(f'  latent54 {md5} :: {count}')
    for md5, count in materialized_md5s.items():
        summary.append(f'  materialized54 {md5} :: {count}')
    summary.append('')
    summary.append('Per-record normalization:')
    for row in normalized_rows:
        summary.append(
            f'  {row["off_hex"]}: form={row["form"]} wrapper={row["wrapper_hex"]} '
            f'core110={row["core110_md5"]} materialized={row["materialized_present"]}'
        )

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'records': len(normalized_rows),
        'forms': Counter(r['form'] for r in normalized_rows),
        'core110_md5_counts': dict(core_md5s),
        'latent54_md5_counts': dict(latent_md5s),
        'materialized54_md5_counts': dict(materialized_md5s),
    }, indent=2, default=lambda x: dict(x)), encoding='utf-8')

if __name__ == '__main__':
    main()
