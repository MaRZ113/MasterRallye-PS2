#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path

RID0C_SIG8 = bytes.fromhex('0000010c423a4a02')
RID0C_LEN = 507
HEAD_LEN = 68

# Family-specific rule learned in v90
STANDALONE_BODY_MD5 = 'c0e70b5dfa4117b3c5d3d71e29053fd1'
TAILED_BODY_MD5 = '57021a2e1879924ce8eb23eb6ea1d261'

STANDALONE_WRAPPER_LEN = 6
STANDALONE_LATENT54_OFF_IN_ZONE = 322
STANDALONE_CORE110_OFF_IN_ZONE = 322

TAILED_WRAPPER_LEN = 4
TAILED_MATERIALIZED54_OFF_IN_ZONE = 314
TAILED_LATENT54_OFF_IN_ZONE = 317
TAILED_CORE110_OFF_IN_ZONE = 317

ZONE_LEN = 432

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

def classify_body(body: bytes) -> str:
    h = md5(body)
    if h == STANDALONE_BODY_MD5:
        return 'standalone'
    if h == TAILED_BODY_MD5:
        return 'tailed'
    return 'unknown'

def main():
    ap = argparse.ArgumentParser(description='BX v91 first family-specific extractor for rid0C 423a4a02')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-rid0c-family')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'extract-rid0c-family':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v91 first family-specific extractor')
    summary.append('=====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append('family: rid0C sig8 0000010c423a4a02')
    summary.append('')

    rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        hits = find_all(mm, RID0C_SIG8)

        summary.append(f'raw_sig8_hits: {len(hits)}')
        summary.append('')

        for idx, off in enumerate(hits, 1):
            if off + RID0C_LEN + ZONE_LEN > mm.size():
                continue

            rec = bytes(mm[off:off + RID0C_LEN])
            if not rec.startswith(RID0C_SIG8):
                continue

            head = rec[:HEAD_LEN]
            body = rec[HEAD_LEN:]
            zone = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ZONE_LEN])

            body_md5 = md5(body)
            form = classify_body(body)

            if form == 'standalone':
                wrapper = zone[316:322]
                latent54 = zone[STANDALONE_LATENT54_OFF_IN_ZONE: STANDALONE_LATENT54_OFF_IN_ZONE + 54]
                core110 = zone[STANDALONE_CORE110_OFF_IN_ZONE: STANDALONE_CORE110_OFF_IN_ZONE + 110]
                materialized54 = b''
                materialized_present = False
            elif form == 'tailed':
                wrapper = zone[313:317]
                latent54 = zone[TAILED_LATENT54_OFF_IN_ZONE: TAILED_LATENT54_OFF_IN_ZONE + 54]
                core110 = zone[TAILED_CORE110_OFF_IN_ZONE: TAILED_CORE110_OFF_IN_ZONE + 110]
                materialized54 = zone[TAILED_MATERIALIZED54_OFF_IN_ZONE: TAILED_MATERIALIZED54_OFF_IN_ZONE + 54]
                materialized_present = materialized54.startswith(bytes.fromhex('0000010d'))
            else:
                # Unknown form: still emit record and raw zone
                wrapper = b''
                latent54 = b''
                core110 = b''
                materialized54 = b''
                materialized_present = False

            hdir = out_dir / f'hit_{idx:02d}_0x{off:X}'
            hdir.mkdir(parents=True, exist_ok=True)

            write_bytes(hdir / 'rid0C_507.bin', rec)
            write_bytes(hdir / 'head68.bin', head)
            write_bytes(hdir / 'body439.bin', body)
            write_bytes(hdir / 'zone432.bin', zone)
            write_bytes(hdir / 'wrapper.bin', wrapper)
            write_bytes(hdir / 'latent54.bin', latent54)
            write_bytes(hdir / 'core110.bin', core110)
            if materialized54:
                write_bytes(hdir / 'materialized54.bin', materialized54)

            meta = {
                'index': idx,
                'off': off,
                'off_hex': f'0x{off:X}',
                'form': form,
                'rid0c_sig8': rec[:8].hex(),
                'body_md5': body_md5,
                'head68_md5': md5(head),
                'zone432_md5': md5(zone),
                'wrapper_hex': wrapper.hex(),
                'latent54_md5': md5(latent54) if latent54 else '',
                'core110_md5': md5(core110) if core110 else '',
                'materialized54_md5': md5(materialized54) if materialized54 else '',
                'materialized_present': materialized_present,
            }
            (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            rows.append({
                'index': idx,
                'off_hex': f'0x{off:X}',
                'form': form,
                'body_md5': body_md5,
                'wrapper_hex': wrapper.hex(),
                'latent54_md5': md5(latent54) if latent54 else '',
                'core110_md5': md5(core110) if core110 else '',
                'materialized54_md5': md5(materialized54) if materialized54 else '',
                'materialized_present': 1 if materialized_present else 0,
            })

            summary.append(
                f'{idx:02d}) 0x{off:X}: form={form} body_md5={body_md5} '
                f'wrapper={wrapper.hex()} latent54={md5(latent54) if latent54 else ""} '
                f'core110={md5(core110) if core110 else ""} materialized={materialized_present}'
            )

        mm.close()

    with (out_dir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['index','off_hex','form','body_md5','wrapper_hex','latent54_md5','core110_md5','materialized54_md5','materialized_present']
        )
        w.writeheader()
        w.writerows(rows)

    rule_summary = {
        'family_sig8': RID0C_SIG8.hex(),
        'record_len': RID0C_LEN,
        'head_len': HEAD_LEN,
        'forms_found': {r['form']: sum(1 for x in rows if x['form'] == r['form']) for r in rows},
        'known_body_md5': {
            'standalone': STANDALONE_BODY_MD5,
            'tailed': TAILED_BODY_MD5,
        },
    }
    (out_dir / 'rule_summary.json').write_text(json.dumps(rule_summary, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
