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

# Optional exact-head families learned from v99
OPTIONAL_FAMILIES = {
    '0000010c423ac340': {'tail_delta': 755},
    '0000010c423a8945': {'tail_delta': 830},
    '0000010c423a4864': {'tail_delta': 920},
}

RID0D_MARKER = b'\x00\x00\x01\x0D'

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

def analyze_pair(standalone_tail: bytes, tailed_tail: bytes):
    res = {
        'standalone_tail_md5': md5(standalone_tail),
        'tailed_tail_md5': md5(tailed_tail),
        'standalone_head16': standalone_tail[:16].hex(),
        'tailed_head16': tailed_tail[:16].hex(),
        'materialized_present': tailed_tail.startswith(RID0D_MARKER),
        'standalone_contains_0d': standalone_tail.find(b'\x0d') != -1,
        'latent_match_if_strip_3': False,
        'strip3_head16': '',
        'strip4_head16': '',
        'latent_match_if_strip_4': False,
    }
    if len(tailed_tail) >= 4:
        strip3 = tailed_tail[3:]
        strip4 = tailed_tail[4:]
        res['strip3_head16'] = strip3[:16].hex()
        res['strip4_head16'] = strip4[:16].hex()
        res['latent_match_if_strip_3'] = strip3 == standalone_tail[:len(strip3)]
        res['latent_match_if_strip_4'] = strip4 == standalone_tail[:len(strip4)]
    return res

def main():
    ap = argparse.ArgumentParser(description='BX v100 optional exact-head class rule miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('mine-optional-exact-head-class')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--after-len', type=int, default=1600)

    ns = ap.parse_args()
    if ns.cmd != 'mine-optional-exact-head-class':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v100 optional exact-head class rule miner')
    summary.append('===========================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'families: {len(OPTIONAL_FAMILIES)}')
    summary.append('')

    family_rows = []
    registry = {}

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for sig8_hex, rule in OPTIONAL_FAMILIES.items():
            sig8 = bytes.fromhex(sig8_hex)
            hits = find_all(mm, sig8)

            fam_dir = out_dir / sig8_hex
            fam_dir.mkdir(parents=True, exist_ok=True)

            recs = []
            for off in hits:
                if off + RID0C_LEN + ns.after_len > mm.size():
                    continue
                rec = bytes(mm[off:off + RID0C_LEN])
                if not rec.startswith(sig8):
                    continue

                after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ns.after_len])

                rel0 = rule['tail_delta'] - RID0C_LEN
                tail = after[rel0:rel0 + TAIL_LEN]
                present = tail.startswith(RID0D_MARKER)
                recs.append({
                    'off': off,
                    'off_hex': f'0x{off:X}',
                    'tail_present': present,
                    'tail': tail,
                })

            standalone = [r for r in recs if not r['tail_present']]
            tailed = [r for r in recs if r['tail_present']]

            analysis = {}
            if standalone and tailed:
                analysis = analyze_pair(standalone[0]['tail'], tailed[0]['tail'])

            # export samples
            for idx, r in enumerate(recs, 1):
                hdir = fam_dir / f'hit_{idx:02d}_{r["off_hex"]}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'tail_candidate_54.bin', r['tail'])
                (hdir / 'tail_candidate_54.hex.txt').write_text(r['tail'].hex(), encoding='utf-8')
                meta = {
                    'off_hex': r['off_hex'],
                    'tail_present': r['tail_present'],
                    'tail_head16': r['tail'][:16].hex(),
                    'tail_md5': md5(r['tail']),
                }
                (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

            row = {
                'family_sig8': sig8_hex,
                'tail_delta': rule['tail_delta'],
                'raw_hits': len(hits),
                'valid_hits': len(recs),
                'standalone_count': len(standalone),
                'tailed_count': len(tailed),
                'standalone_tail_md5': analysis.get('standalone_tail_md5', ''),
                'tailed_tail_md5': analysis.get('tailed_tail_md5', ''),
                'latent_match_if_strip_3': 1 if analysis.get('latent_match_if_strip_3') else 0,
                'latent_match_if_strip_4': 1 if analysis.get('latent_match_if_strip_4') else 0,
                'tailed_head16': analysis.get('tailed_head16', ''),
                'standalone_head16': analysis.get('standalone_head16', ''),
            }
            family_rows.append(row)

            registry[sig8_hex] = {
                'class': 'optional_exact_head',
                'tail_delta': rule['tail_delta'],
                'standalone_count': len(standalone),
                'tailed_count': len(tailed),
                'analysis': analysis,
            }

            summary.append(
                f'[{sig8_hex}] tail_delta={rule["tail_delta"]} '
                f'valid={len(recs)} standalone={len(standalone)} tailed={len(tailed)}'
            )
            if analysis:
                summary.append(f'  standalone_head16={analysis["standalone_head16"]}')
                summary.append(f'  tailed_head16={analysis["tailed_head16"]}')
                summary.append(f'  strip3_match={analysis["latent_match_if_strip_3"]}')
                summary.append(f'  strip4_match={analysis["latent_match_if_strip_4"]}')
            summary.append('')

        mm.close()

    with (out_dir / 'class_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                'family_sig8','tail_delta','raw_hits','valid_hits','standalone_count','tailed_count',
                'standalone_tail_md5','tailed_tail_md5','latent_match_if_strip_3','latent_match_if_strip_4',
                'tailed_head16','standalone_head16'
            ]
        )
        w.writeheader()
        w.writerows(family_rows)

    (out_dir / 'registry.json').write_text(json.dumps(registry, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
