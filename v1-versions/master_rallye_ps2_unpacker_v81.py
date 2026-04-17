#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import struct
from collections import Counter, defaultdict
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def u16le(b: bytes, off: int) -> int:
    return struct.unpack_from('<H', b, off)[0]

def u16be(b: bytes, off: int) -> int:
    return struct.unpack_from('>H', b, off)[0]

def u32le(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]

def u32be(b: bytes, off: int) -> int:
    return struct.unpack_from('>I', b, off)[0]

def find_zero_runs(data: bytes, min_len: int = 2):
    runs = []
    i = 0
    while i < len(data):
        if data[i] != 0:
            i += 1
            continue
        j = i
        while j < len(data) and data[j] == 0:
            j += 1
        if j - i >= min_len:
            runs.append((i, j - i))
        i = j
    return runs

def repeating_ngrams(data: bytes, n: int, min_count: int = 2):
    cnt = Counter(data[i:i+n] for i in range(0, len(data)-n+1))
    return [(k, v) for k, v in cnt.items() if v >= min_count]

def main():
    ap = argparse.ArgumentParser(description='BX v81 rid0C normalized core anatomy miner')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('anatomy-rid0c-core')
    p.add_argument('v79_root', type=Path)
    p.add_argument('out_dir', type=Path)
    p.add_argument('--window', type=int, default=32)
    p.add_argument('--step', type=int, default=16)

    ns = ap.parse_args()
    if ns.cmd != 'anatomy-rid0c-core':
        raise SystemExit(1)

    v79_root: Path = ns.v79_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    core = read_bytes(v79_root / 'shared_core.bin')
    v1p = read_bytes(v79_root / 'variant1_prefix.bin')
    v2p = read_bytes(v79_root / 'variant2_prefix.bin')
    v2s = read_bytes(v79_root / 'variant2_suffix.bin')

    summary = []
    summary.append('BX v81 rid0C normalized core anatomy')
    summary.append('====================================')
    summary.append(f'core_len: {len(core)}')
    summary.append(f'variant1_prefix_len: {len(v1p)}')
    summary.append(f'variant2_prefix_len: {len(v2p)}')
    summary.append(f'variant2_suffix_len: {len(v2s)}')
    summary.append(f'core_head16: {core[:16].hex()}')
    summary.append(f'core_tail16: {core[-16:].hex()}')
    summary.append('')

    # rolling entropy
    ent_rows = []
    for off in range(0, max(1, len(core) - ns.window + 1), ns.step):
        chunk = core[off:off+ns.window]
        ent_rows.append({
            'off': off,
            'len': len(chunk),
            'entropy': round(entropy(chunk), 6),
            'head8': chunk[:8].hex(),
        })

    with (out_dir / 'rolling_entropy.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','len','entropy','head8'])
        w.writeheader()
        w.writerows(ent_rows)

    # aligned word scan
    word_rows = []
    for off in range(0, len(core) - 3, 4):
        le = u32le(core, off)
        be = u32be(core, off)
        word_rows.append({
            'off': off,
            'hex4': core[off:off+4].hex(),
            'u32_le': f'0x{le:08X}',
            'u32_be': f'0x{be:08X}',
            'small_le': 1 if 0 < le <= len(core) else 0,
            'small_be': 1 if 0 < be <= len(core) else 0,
        })

    with (out_dir / 'aligned_u32_scan.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','hex4','u32_le','u32_be','small_le','small_be'])
        w.writeheader()
        w.writerows(word_rows)

    # byte frequency and zero runs
    freq = Counter(core)
    with (out_dir / 'byte_frequency.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['byte_hex','count'])
        w.writeheader()
        for b, count in freq.most_common():
            w.writerow({'byte_hex': f'{b:02X}', 'count': count})

    zero_rows = [{'start': s, 'len': l} for s, l in find_zero_runs(core, 2)]
    with (out_dir / 'zero_runs.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['start','len'])
        w.writeheader()
        w.writerows(zero_rows)

    # repeated ngrams
    rep4 = repeating_ngrams(core, 4, 2)
    rep8 = repeating_ngrams(core, 8, 2)

    with (out_dir / 'repeat_4grams.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['hex','count'])
        w.writeheader()
        for blob, count in sorted(rep4, key=lambda x: (-x[1], x[0])):
            w.writerow({'hex': blob.hex(), 'count': count})

    with (out_dir / 'repeat_8grams.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['hex','count'])
        w.writeheader()
        for blob, count in sorted(rep8, key=lambda x: (-x[1], x[0])):
            w.writerow({'hex': blob.hex(), 'count': count})

    # wrapper summary
    wrap = {
        'variant1_prefix_hex': v1p.hex(),
        'variant2_prefix_hex': v2p.hex(),
        'variant2_suffix_hex': v2s.hex(),
    }
    (out_dir / 'wrapper_summary.json').write_text(json.dumps(wrap, indent=2), encoding='utf-8')

    # human summary
    summary.append(f'core_entropy_full: {entropy(core):.6f}')
    summary.append(f'zero_run_count: {len(zero_rows)}')
    summary.append(f'repeat_4gram_count: {len(rep4)}')
    summary.append(f'repeat_8gram_count: {len(rep8)}')
    summary.append('')
    summary.append('Zero runs:')
    for row in zero_rows[:32]:
        summary.append(f'  start={row["start"]} len={row["len"]}')
    summary.append('')
    summary.append('Top repeat 4-grams:')
    for blob, count in sorted(rep4, key=lambda x: (-x[1], x[0]))[:20]:
        summary.append(f'  {blob.hex()} :: {count}')
    summary.append('')
    summary.append('Candidate small aligned u32:')
    shown = 0
    for row in word_rows:
        if row['small_le'] or row['small_be']:
            summary.append(
                f'  off={row["off"]} hex={row["hex4"]} le={row["u32_le"]} be={row["u32_be"]} '
                f'small_le={row["small_le"]} small_be={row["small_be"]}'
            )
            shown += 1
            if shown >= 24:
                break

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')
    (out_dir / 'meta.json').write_text(json.dumps({
        'core_len': len(core),
        'core_entropy_full': entropy(core),
        'zero_run_count': len(zero_rows),
        'repeat_4gram_count': len(rep4),
        'repeat_8gram_count': len(rep8),
    }, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
