#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, math, os
from pathlib import Path
from collections import Counter

FOCUS_RIDS = [1,5,6,7,9,10,13,15]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def load_rid_bank(root: Path, rid: int) -> list[tuple[str, bytes]]:
    # folders like rid_01_header, rid_05_descriptor, rid_09_data
    candidates = list((root / 'rid_banks').glob(f'rid_{rid:02d}_*'))
    if not candidates:
        return []
    bank = candidates[0]
    out = []
    for p in sorted(bank.glob('*.bin')):
        out.append((p.stem, p.read_bytes()))
    return out


def family_stats(samples: list[bytes]) -> dict:
    if not samples:
        return {}
    lens = [len(s) for s in samples]
    minlen = min(lens)
    maxlen = max(lens)
    common_prefix = 0
    for i in range(minlen):
        b0 = samples[0][i]
        if all(s[i] == b0 for s in samples[1:]):
            common_prefix += 1
        else:
            break
    common_suffix = 0
    for i in range(1, minlen+1):
        b0 = samples[0][-i]
        if all(s[-i] == b0 for s in samples[1:]):
            common_suffix += 1
        else:
            break
    return {
        'count': len(samples),
        'min_len': minlen,
        'max_len': maxlen,
        'median_len': sorted(lens)[len(lens)//2],
        'avg_entropy': round(sum(entropy(s) for s in samples) / len(samples), 4),
        'common_prefix': common_prefix,
        'common_suffix': common_suffix,
    }


def offset_table(full: list[bytes], variant: list[bytes]) -> list[dict]:
    max_len = max([len(x) for x in full + variant], default=0)
    rows = []
    for off in range(max_len):
        fvals = [s[off] for s in full if off < len(s)]
        vvals = [s[off] for s in variant if off < len(s)]
        fset = sorted(set(fvals))
        vset = sorted(set(vvals))
        fconst = len(fset) == 1 and len(fvals) == len(full) and len(full) > 0
        vconst = len(vset) == 1 and len(vvals) == len(variant) and len(variant) > 0
        classification = 'other'
        if fconst and vconst and fset[0] == vset[0]:
            classification = 'shared_constant'
        elif fconst and vconst and fset[0] != vset[0]:
            classification = 'family_discriminator'
        elif fconst and not vconst:
            classification = 'full_constant_only'
        elif vconst and not fconst:
            classification = 'variant_constant_only'
        elif 0 < len(fset) <= 3 or 0 < len(vset) <= 3:
            classification = 'small_enum_candidate'
        rows.append({
            'offset': off,
            'full_present': len(fvals),
            'variant_present': len(vvals),
            'full_distinct': len(fset),
            'variant_distinct': len(vset),
            'full_values_hex': ' '.join(f'{x:02X}' for x in fset[:16]),
            'variant_values_hex': ' '.join(f'{x:02X}' for x in vset[:16]),
            'classification': classification,
        })
    return rows


def write_hex_matrix(samples: list[tuple[str, bytes]], out_csv: Path):
    if not samples:
        return
    max_len = max(len(b) for _, b in samples)
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['sample'] + [f'{i:04X}' for i in range(max_len)])
        for name, blob in samples:
            row = [name] + [f'{blob[i]:02X}' if i < len(blob) else '' for i in range(max_len)]
            w.writerow(row)


def analyze(full_root: Path, variant_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    rid_compare_rows = []
    summary_lines = []
    summary_lines.append('BX v18 field atlas')
    summary_lines.append('=================')
    summary_lines.append(f'full_root: {full_root}')
    summary_lines.append(f'variant_root: {variant_root}')
    summary_lines.append('')

    for rid in FOCUS_RIDS:
        full_bank = load_rid_bank(full_root, rid)
        var_bank = load_rid_bank(variant_root, rid)
        full_blobs = [b for _, b in full_bank]
        var_blobs = [b for _, b in var_bank]
        rid_dir = out_dir / f'rid_{rid:02d}'
        rid_dir.mkdir(exist_ok=True)

        write_hex_matrix(full_bank, rid_dir / 'full_hex_matrix.csv')
        write_hex_matrix(var_bank, rid_dir / 'variant_hex_matrix.csv')

        fstats = family_stats(full_blobs)
        vstats = family_stats(var_blobs)
        rows = offset_table(full_blobs, var_blobs)
        with (rid_dir / 'offset_field_table.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['offset'])
            w.writeheader()
            for r in rows:
                w.writerow(r)

        discr = [r for r in rows if r['classification'] == 'family_discriminator']
        shared = [r for r in rows if r['classification'] == 'shared_constant']
        fenum = [r for r in rows if r['classification'] == 'small_enum_candidate']
        result = {
            'rid': rid,
            'full': fstats,
            'variant': vstats,
            'family_discriminator_offsets': [r['offset'] for r in discr[:64]],
            'shared_constant_offsets': [r['offset'] for r in shared[:64]],
            'small_enum_candidate_offsets': [r['offset'] for r in fenum[:64]],
        }
        (rid_dir / 'summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        rid_compare_rows.append({
            'rid': rid,
            'full_median_len': fstats.get('median_len'),
            'variant_median_len': vstats.get('median_len'),
            'full_common_prefix': fstats.get('common_prefix'),
            'variant_common_prefix': vstats.get('common_prefix'),
            'full_common_suffix': fstats.get('common_suffix'),
            'variant_common_suffix': vstats.get('common_suffix'),
            'family_discriminator_count': len(discr),
            'shared_constant_count': len(shared),
            'small_enum_candidate_count': len(fenum),
        })
        summary_lines.append(
            f"rid {rid:02d}: full_med={fstats.get('median_len')} var_med={vstats.get('median_len')} "
            f"discr={len(discr)} shared={len(shared)} enumish={len(fenum)}"
        )
    with (out_dir / 'rid_atlas_compare.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rid_compare_rows[0].keys()))
        w.writeheader()
        for r in rid_compare_rows:
            w.writerow(r)
    (out_dir / 'summary.txt').write_text('\n'.join(summary_lines), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description='BX v18 field atlas')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('atlas-fields')
    p.add_argument('full_root', type=Path)
    p.add_argument('variant_root', type=Path)
    p.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'atlas-fields':
        analyze(ns.full_root, ns.variant_root, ns.out_dir)

if __name__ == '__main__':
    main()
