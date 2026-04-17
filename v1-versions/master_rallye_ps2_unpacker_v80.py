#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import csv
import gzip
import json
import lzma
import zlib
from pathlib import Path

MAGICS = [
    b'ELF', b'DDS ', b'RIFF', b'TIM2', b'<?xml', b'<Egg', b'AI_List',
    b'PNG', b'OggS', b'PK\x03\x04', b'\x1f\x8b', b'BZh',
    b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'JFIF', b'BM', b'WAVE'
]

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def scan_magics(data: bytes):
    found = []
    for m in MAGICS:
        off = data.find(m)
        if off != -1:
            try:
                name = m.decode('latin1')
            except Exception:
                name = m.hex()
            found.append({'magic': name, 'off': off})
    return found

def swap16(data: bytes) -> bytes:
    out = bytearray()
    n = len(data) - (len(data) % 2)
    for i in range(0, n, 2):
        out.extend(data[i:i+2][::-1])
    out.extend(data[n:])
    return bytes(out)

def swap32(data: bytes) -> bytes:
    out = bytearray()
    n = len(data) - (len(data) % 4)
    for i in range(0, n, 4):
        out.extend(data[i:i+4][::-1])
    out.extend(data[n:])
    return bytes(out)

def xor_ff(data: bytes) -> bytes:
    return bytes((b ^ 0xFF) for b in data)

def try_zlib_variants(data: bytes):
    out = []
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 15 | 32):
        try:
            blob = zlib.decompress(data, wbits)
            out.append((f'zlib_wbits_{wbits}', blob))
        except Exception:
            pass
    return out

def try_all(blob: bytes):
    results = [('identity', blob)]
    variants = {
        'skip1': blob[1:],
        'skip2': blob[2:],
        'skip3': blob[3:],
        'skip4': blob[4:],
        'skip6': blob[6:],
        'skip8': blob[8:],
        'swap16': swap16(blob),
        'swap32': swap32(blob),
        'xor_ff': xor_ff(blob),
        'reverse': blob[::-1],
    }
    for name, data in variants.items():
        results.append((name, data))

    sources = {'orig': blob, 'skip1': blob[1:], 'skip2': blob[2:], 'skip3': blob[3:], 'skip4': blob[4:], 'skip6': blob[6:], 'skip8': blob[8:]}
    for sname, data in sources.items():
        try:
            results.append((f'gzip_{sname}', gzip.decompress(data)))
        except Exception:
            pass
        try:
            results.append((f'bz2_{sname}', bz2.decompress(data)))
        except Exception:
            pass
        try:
            results.append((f'lzma_{sname}', lzma.decompress(data)))
        except Exception:
            pass
        for name, dec in try_zlib_variants(data):
            results.append((f'{name}_{sname}', dec))

    uniq = []
    seen = set()
    for name, data in results:
        key = (len(data), data[:64], data[-64:] if len(data) >= 64 else data)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((name, data))
    return uniq

def process_blob(label: str, blob: bytes, out_root: Path, summary: list, manifest_rows: list):
    bdir = out_root / label
    bdir.mkdir(parents=True, exist_ok=True)
    write_bytes(bdir / 'source.bin', blob)
    (bdir / 'source.hex.txt').write_text(blob.hex(), encoding='utf-8')

    results = try_all(blob)
    summary.append(f'[{label}] input_len={len(blob)}')
    interesting = 0

    for name, data in results:
        magics = scan_magics(data)
        if magics or len(data) != len(blob):
            interesting += 1
            write_bytes(bdir / f'{name}.bin', data)
            manifest_rows.append({
                'label': label,
                'transform': name,
                'out_len': len(data),
                'magics': json.dumps(magics, ensure_ascii=False),
            })
            summary.append(f'  {name}: len={len(data)} magics={magics}')

    if interesting == 0:
        summary.append('  no obvious decoded/magic-bearing outputs')
    summary.append('')

def main():
    ap = argparse.ArgumentParser(description='BX v80 rid0C normalized core probe')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-rid0c-core')
    p.add_argument('v79_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'probe-rid0c-core':
        raise SystemExit(1)

    v79_root: Path = ns.v79_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v80 rid0C normalized core probe')
    summary.append('==================================')
    summary.append(f'v79_root: {v79_root}')
    summary.append('')

    manifest_rows = []

    process_blob('shared_core', read_bytes(v79_root / 'shared_core.bin'), out_dir, summary, manifest_rows)
    process_blob('variant1_prefix', read_bytes(v79_root / 'variant1_prefix.bin'), out_dir, summary, manifest_rows)
    process_blob('variant2_prefix', read_bytes(v79_root / 'variant2_prefix.bin'), out_dir, summary, manifest_rows)
    process_blob('variant2_suffix', read_bytes(v79_root / 'variant2_suffix.bin'), out_dir, summary, manifest_rows)

    with (out_dir / 'probe_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['label','transform','out_len','magics'])
        w.writeheader()
        w.writerows(manifest_rows)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
