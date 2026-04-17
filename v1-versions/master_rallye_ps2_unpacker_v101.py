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

# Learned from v100:
# standalone tail contains embedded 0D at latent_off,
# tailed form materializes it by replacing the leading bytes with 000001
OPTIONAL_EXACT_HEAD_REGISTRY = {
    '0000010c423ac340': {'tail_delta': 755, 'latent_off': 4},
    '0000010c423a8945': {'tail_delta': 830, 'latent_off': 10},
    '0000010c423a4864': {'tail_delta': 920, 'latent_off': 4},
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
    ap = argparse.ArgumentParser(description='BX v101 optional exact-head class rule emitter')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('emit-optional-exact-head-rules')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--after-len', type=int, default=1600)

    ns = ap.parse_args()
    if ns.cmd != 'emit-optional-exact-head-rules':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v101 optional exact-head class rule emitter')
    summary.append('============================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'families: {len(OPTIONAL_EXACT_HEAD_REGISTRY)}')
    summary.append('')

    manifest_rows = []
    registry_out = {}

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for sig8_hex, rule in OPTIONAL_EXACT_HEAD_REGISTRY.items():
            sig8 = bytes.fromhex(sig8_hex)
            tail_delta = rule['tail_delta']
            latent_off = rule['latent_off']

            hits = find_all(mm, sig8)
            recs = []

            for off in hits:
                if off + RID0C_LEN + ns.after_len > mm.size():
                    continue
                rec = bytes(mm[off:off + RID0C_LEN])
                if not rec.startswith(sig8):
                    continue
                after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ns.after_len])

                rel0 = tail_delta - RID0C_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_present = tail.startswith(RID0D_MARKER)

                recs.append({
                    'off': off,
                    'off_hex': f'0x{off:X}',
                    'tail': tail,
                    'tail_md5': md5(tail),
                    'tail_present': tail_present,
                })

            standalone = [r for r in recs if not r['tail_present']]
            tailed = [r for r in recs if r['tail_present']]

            # Use first samples of each form to verify class rule
            standalone_tail = standalone[0]['tail'] if standalone else b''
            tailed_tail = tailed[0]['tail'] if tailed else b''

            materialized_match = False
            compared_len = 0
            if standalone_tail and tailed_tail and latent_off < len(standalone_tail):
                compared_len = min(len(tailed_tail) - 3, len(standalone_tail) - latent_off)
                materialized_match = (
                    tailed_tail.startswith(RID0D_MARKER) and
                    tailed_tail[3:3+compared_len] == standalone_tail[latent_off:latent_off+compared_len]
                )

            fam_dir = out_dir / sig8_hex
            fam_dir.mkdir(parents=True, exist_ok=True)

            for idx, r in enumerate(recs, 1):
                hdir = fam_dir / f'hit_{idx:02d}_{r["off_hex"]}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'tail_candidate_54.bin', r['tail'])
                (hdir / 'tail_candidate_54.hex.txt').write_text(r['tail'].hex(), encoding='utf-8')
                meta = {
                    'off_hex': r['off_hex'],
                    'tail_md5': r['tail_md5'],
                    'tail_present': r['tail_present'],
                }
                (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

                manifest_rows.append({
                    'family_sig8': sig8_hex,
                    'off_hex': r['off_hex'],
                    'tail_present': 1 if r['tail_present'] else 0,
                    'tail_md5': r['tail_md5'],
                })

            registry_out[sig8_hex] = {
                'class': 'optional_exact_head',
                'tail_delta': tail_delta,
                'latent_off': latent_off,
                'standalone_count': len(standalone),
                'tailed_count': len(tailed),
                'standalone_tail_md5': standalone[0]['tail_md5'] if standalone else '',
                'tailed_tail_md5': tailed[0]['tail_md5'] if tailed else '',
                'materialized_prefix': '000001',
                'materialized_match': materialized_match,
                'compared_len': compared_len,
            }

            summary.append(
                f'[{sig8_hex}] tail_delta={tail_delta} latent_off={latent_off} '
                f'standalone={len(standalone)} tailed={len(tailed)} materialized_match={materialized_match} compare={compared_len}'
            )
            if standalone_tail:
                summary.append(f'  standalone_head16={standalone_tail[:16].hex()}')
            if tailed_tail:
                summary.append(f'  tailed_head16={tailed_tail[:16].hex()}')
            summary.append('')

        mm.close()

    with (out_dir / 'class_extract_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['family_sig8','off_hex','tail_present','tail_md5'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'optional_exact_head_registry.json').write_text(json.dumps(registry_out, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
