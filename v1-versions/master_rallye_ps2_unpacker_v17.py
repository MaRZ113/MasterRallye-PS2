#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, math, os, statistics
from pathlib import Path
from collections import Counter, defaultdict

FOCUS_RIDS = [1,5,6,7,9,10,13,15]


def read_bytes(p: Path) -> bytes:
    return p.read_bytes()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def gather_rid_bank(root: Path, rid: int):
    # root/rid_banks/rid_XX_*/chain_*.bin
    rid_dir = root / 'rid_banks'
    hits = []
    if not rid_dir.exists():
        return hits
    prefix = f'rid_{rid:02d}_'
    for sub in rid_dir.iterdir():
        if sub.is_dir() and sub.name.startswith(prefix):
            for f in sorted(sub.glob('*.bin')):
                hits.append((sub.name, f.name, read_bytes(f)))
    return hits


def common_prefix(vals: list[bytes]) -> int:
    if not vals:
        return 0
    m = min(len(v) for v in vals)
    n = 0
    for i in range(m):
        b = vals[0][i]
        if all(v[i] == b for v in vals[1:]):
            n += 1
        else:
            break
    return n


def common_suffix(vals: list[bytes]) -> int:
    if not vals:
        return 0
    m = min(len(v) for v in vals)
    n = 0
    for i in range(1, m + 1):
        b = vals[0][-i]
        if all(v[-i] == b for v in vals[1:]):
            n += 1
        else:
            break
    return n


def stable_mask(vals: list[bytes], maxlen: int | None = None) -> str:
    if not vals:
        return ''
    m = min(len(v) for v in vals)
    if maxlen is not None:
        m = min(m, maxlen)
    out = []
    for i in range(m):
        bs = {v[i] for v in vals}
        if len(bs) == 1:
            out.append(f'{next(iter(bs)):02X}')
        else:
            out.append('..')
    return ' '.join(out)


def family_constant_offsets(vals: list[bytes]):
    if not vals:
        return {}
    m = min(len(v) for v in vals)
    out = {}
    for i in range(m):
        bs = {v[i] for v in vals}
        if len(bs) == 1:
            out[i] = next(iter(bs))
    return out


def differential_constant_offsets(full_vals: list[bytes], var_vals: list[bytes]):
    f = family_constant_offsets(full_vals)
    v = family_constant_offsets(var_vals)
    offsets = sorted(set(f) & set(v))
    diffs = []
    for off in offsets:
        if f[off] != v[off]:
            diffs.append((off, f[off], v[off]))
    return diffs


def numeric_field_scan(vals: list[bytes], widths=(1,2,4)):
    # candidate enum/field offsets: low cardinality across samples
    out = []
    if not vals:
        return out
    m = min(len(v) for v in vals)
    for width in widths:
        for off in range(0, m - width + 1):
            rawset = {v[off:off+width] for v in vals}
            if 1 < len(rawset) <= min(4, len(vals)):
                le_vals = sorted({int.from_bytes(x, 'little') for x in rawset})
                be_vals = sorted({int.from_bytes(x, 'big') for x in rawset})
                out.append({
                    'off': off,
                    'width': width,
                    'distinct': len(rawset),
                    'le_vals': le_vals,
                    'be_vals': be_vals,
                })
    return out


def write_hex_matrix(samples: list[tuple[str,str,bytes]], out_csv: Path, max_bytes: int = 64):
    headers = ['bank_dir', 'file', 'size'] + [f'b{i:02d}' for i in range(max_bytes)]
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(headers)
        for bank_dir, name, data in samples:
            row = [bank_dir, name, len(data)]
            for i in range(max_bytes):
                row.append(f'{data[i]:02X}' if i < len(data) else '')
            w.writerow(row)


def summarize_family(samples):
    vals = [d for _,_,d in samples]
    return {
        'count': len(vals),
        'median_size': int(statistics.median(len(v) for v in vals)) if vals else 0,
        'common_prefix': common_prefix(vals),
        'common_suffix': common_suffix(vals),
        'avg_entropy': round(statistics.mean(entropy(v) for v in vals), 4) if vals else 0.0,
        'stable_mask_64': stable_mask(vals, 64),
    }


def main():
    ap = argparse.ArgumentParser(description='BX v17 rid field miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    a = sub.add_parser('mine-rids')
    a.add_argument('full_root', type=Path)
    a.add_argument('variant_root', type=Path)
    a.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd == 'mine-rids':
        out = ns.out_dir
        out.mkdir(parents=True, exist_ok=True)
        summary_lines = []
        compare_rows = []
        for rid in FOCUS_RIDS:
            full = gather_rid_bank(ns.full_root, rid)
            var = gather_rid_bank(ns.variant_root, rid)
            rid_dir = out / f'rid_{rid:02d}'
            rid_dir.mkdir(parents=True, exist_ok=True)
            write_hex_matrix(full, rid_dir / 'full_hex_matrix.csv')
            write_hex_matrix(var, rid_dir / 'variant_hex_matrix.csv')
            full_sum = summarize_family(full)
            var_sum = summarize_family(var)
            diff_offs = differential_constant_offsets([d for _,_,d in full], [d for _,_,d in var])
            enum_full = numeric_field_scan([d for _,_,d in full])
            enum_var = numeric_field_scan([d for _,_,d in var])
            (rid_dir / 'summary.json').write_text(json.dumps({
                'rid': rid,
                'full': full_sum,
                'variant': var_sum,
                'differential_constant_offsets': [
                    {'off': off, 'full': f'{fb:02X}', 'variant': f'{vb:02X}'} for off, fb, vb in diff_offs
                ],
                'enum_candidates_full': enum_full[:100],
                'enum_candidates_variant': enum_var[:100],
            }, indent=2), encoding='utf-8')
            compare_rows.append({
                'rid': rid,
                'full_count': full_sum['count'],
                'variant_count': var_sum['count'],
                'full_median_size': full_sum['median_size'],
                'variant_median_size': var_sum['median_size'],
                'full_common_prefix': full_sum['common_prefix'],
                'variant_common_prefix': var_sum['common_prefix'],
                'full_common_suffix': full_sum['common_suffix'],
                'variant_common_suffix': var_sum['common_suffix'],
                'full_avg_entropy': full_sum['avg_entropy'],
                'variant_avg_entropy': var_sum['avg_entropy'],
                'differential_constant_offsets': len(diff_offs),
            })
            summary_lines.append(
                f"rid {rid:02d}: full_med={full_sum['median_size']} var_med={var_sum['median_size']} "
                f"full_pref={full_sum['common_prefix']} var_pref={var_sum['common_prefix']} "
                f"diff_const={len(diff_offs)}"
            )
        # write compare csv
        with (out / 'rid_field_compare.csv').open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(compare_rows[0].keys()))
            w.writeheader(); w.writerows(compare_rows)
        (out / 'summary.txt').write_text(
            'BX v17 rid field miner\n=======================\n' + '\n'.join(summary_lines) +
            '\n\nNext manual focus:\n- rid 01: header bytes and family discriminator\n- rid 05-07: descriptor byte positions with family-specific constants\n- rid 09/10/13/15: payload data layer\n',
            encoding='utf-8'
        )
        print((out / 'summary.txt').read_text(encoding='utf-8'))

if __name__ == '__main__':
    main()
