#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import mmap
from pathlib import Path

RID0C_LEN = 507
TAIL_LEN = 54
RID0D_MARKER = b'\x00\x00\x01\x0D'

REGISTRY = {
    # exact-head + fixed-tail class
    '0000010c423a40ae': {'mode': 'fixed_tail', 'tail_delta': 781},
    '0000010c423a0063': {'mode': 'fixed_tail', 'tail_delta': 695},
    '0000010c423ad082': {'mode': 'fixed_tail', 'tail_delta': 874},
    '0000010c423ac0c0': {'mode': 'fixed_tail', 'tail_delta': 795},
    '0000010c423ac02c': {'mode': 'fixed_tail', 'tail_delta': 1278},
    '0000010c423a4b1a': {'mode': 'fixed_tail', 'tail_delta': 771},

    # mixed optional exact-head class
    '0000010c423ac340': {'mode': 'optional_tail', 'tail_delta': 755},
    '0000010c423a8945': {'mode': 'optional_tail', 'tail_delta': 830},
    '0000010c423a4864': {'mode': 'optional_tail', 'tail_delta': 920},
}

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
    ap = argparse.ArgumentParser(description='BX v99 exact-head rid0C class extractor')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('extract-exact-head-class')
    p.add_argument('tng_path', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--after-len', type=int, default=1600)

    ns = ap.parse_args()
    if ns.cmd != 'extract-exact-head-class':
        raise SystemExit(1)

    tng_path: Path = ns.tng_path
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v99 exact-head rid0C class extractor')
    summary.append('====================================')
    summary.append(f'tng_path: {tng_path}')
    summary.append(f'families: {len(REGISTRY)}')
    summary.append('')

    all_rows = []

    with tng_path.open('rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for sig8_hex, rule in REGISTRY.items():
            sig8 = bytes.fromhex(sig8_hex)
            fam_dir = out_dir / sig8_hex
            fam_dir.mkdir(parents=True, exist_ok=True)

            hits = find_all(mm, sig8)
            summary.append(f'[{sig8_hex}] mode={rule["mode"]} raw_hits={len(hits)}')

            fam_rows = []
            for idx, off in enumerate(hits, 1):
                if off + RID0C_LEN + ns.after_len > mm.size():
                    continue

                rec = bytes(mm[off:off + RID0C_LEN])
                if not rec.startswith(sig8):
                    continue

                after = bytes(mm[off + RID0C_LEN: off + RID0C_LEN + ns.after_len])

                tail_delta = rule['tail_delta']
                rel0 = max(0, tail_delta - RID0C_LEN)
                tail_gap = after[:rel0]
                tail = after[rel0:rel0 + TAIL_LEN]
                tail_post = after[rel0 + TAIL_LEN:]

                tail_present = tail.startswith(RID0D_MARKER)
                observed_tail_sig8 = tail[:8].hex() if len(tail) >= 8 else ''

                hdir = fam_dir / f'hit_{idx:02d}_0x{off:X}'
                hdir.mkdir(parents=True, exist_ok=True)
                write_bytes(hdir / 'rid0C_507.bin', rec)
                write_bytes(hdir / 'after.bin', after)
                write_bytes(hdir / 'tail_gap.bin', tail_gap)
                write_bytes(hdir / 'tail_candidate_54.bin', tail)
                write_bytes(hdir / 'tail_post.bin', tail_post)

                meta = {
                    'index': idx,
                    'off': off,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'mode': rule['mode'],
                    'tail_delta': tail_delta,
                    'tail_present': tail_present,
                    'observed_tail_sig8': observed_tail_sig8,
                }
                (hdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

                row = {
                    'index': idx,
                    'off_hex': f'0x{off:X}',
                    'family_sig8': sig8_hex,
                    'mode': rule['mode'],
                    'tail_delta': tail_delta,
                    'tail_present': 1 if tail_present else 0,
                    'observed_tail_sig8': observed_tail_sig8,
                }
                fam_rows.append(row)
                all_rows.append(row)

            with (fam_dir / 'extract_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
                w = csv.DictWriter(
                    f_csv,
                    fieldnames=['index','off_hex','family_sig8','mode','tail_delta','tail_present','observed_tail_sig8']
                )
                w.writeheader()
                w.writerows(fam_rows)

            present = sum(r['tail_present'] for r in fam_rows)
            summary.append(f'  extracted={len(fam_rows)} tail_present={present}')
            summary.append('')

        mm.close()

    with (out_dir / 'framework_manifest.csv').open('w', encoding='utf-8', newline='') as f_csv:
        w = csv.DictWriter(
            f_csv,
            fieldnames=['index','off_hex','family_sig8','mode','tail_delta','tail_present','observed_tail_sig8']
        )
        w.writeheader()
        w.writerows(all_rows)

    (out_dir / 'registry.json').write_text(json.dumps(REGISTRY, indent=2), encoding='utf-8')
    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
