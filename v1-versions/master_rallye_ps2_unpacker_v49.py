#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import gzip
import json
import lzma
import struct
import zlib
from pathlib import Path

MAGICS = [
    b'ELF', b'DDS ', b'RIFF', b'TIM2', b'<?xml', b'<Egg', b'AI_List',
    b'PNG', b'OggS', b'PK\x03\x04', b'\x1f\x8b', b'BZh',
    b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'BX'
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
    results = []
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 15 | 32):
        try:
            out = zlib.decompress(data, wbits)
            results.append((f'zlib_wbits_{wbits}', out))
        except Exception:
            pass
    return results

def try_all_decoders(data: bytes):
    results = []

    # raw identity scan
    results.append(('identity', data))

    # common byte transforms
    transforms = {
        'skip4': data[4:],
        'skip8': data[8:],
        'skip16': data[16:],
        'xor_ff': xor_ff(data),
        'swap16': swap16(data),
        'swap32': swap32(data),
        'reverse': data[::-1],
    }
    for name, blob in transforms.items():
        results.append((name, blob))

    # decompress on original + sliced inputs
    sources = {
        'orig': data,
        'skip4': data[4:],
        'skip8': data[8:],
        'skip16': data[16:],
    }

    for sname, blob in sources.items():
        # gzip
        try:
            out = gzip.decompress(blob)
            results.append((f'gzip_{sname}', out))
        except Exception:
            pass
        # bz2
        try:
            out = bz2.decompress(blob)
            results.append((f'bz2_{sname}', out))
        except Exception:
            pass
        # lzma/xz
        try:
            out = lzma.decompress(blob)
            results.append((f'lzma_{sname}', out))
        except Exception:
            pass
        # zlib variants
        for name, out in try_zlib_variants(blob):
            results.append((f'{name}_{sname}', out))

    # dedupe by content
    uniq = []
    seen = set()
    for name, blob in results:
        key = (len(blob), blob[:64], blob[-64:] if len(blob) >= 64 else blob)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((name, blob))
    return uniq

def main():
    ap = argparse.ArgumentParser(description='BX v49 format probe for singleton rid0A and rid08 bodies')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-formats')
    p.add_argument('v47_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'probe-formats':
        raise SystemExit(1)

    root: Path = ns.v47_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = []

    rid0a = root / 'singleton_rid_0A' / 'record.bin'
    if rid0a.exists():
        targets.append(('rid0A_record', rid0a))

    rid08 = root / 'comparative_rid_08'
    if rid08.exists():
        for p in sorted(rid08.glob('*_body.bin')):
            targets.append((p.stem, p))

    summary = []
    summary.append('BX v49 format probe')
    summary.append('==================')
    summary.append(f'v47_root: {root}')
    summary.append('')

    manifest = []

    for label, path in targets:
        data = read_bytes(path)
        tdir = out_dir / label
        tdir.mkdir(parents=True, exist_ok=True)

        results = try_all_decoders(data)

        summary.append(f'[{label}] input_len={len(data)}')
        interesting = 0

        for name, blob in results:
            magics = scan_magics(blob)
            out_path = tdir / f'{name}.bin'
            write_bytes(out_path, blob)
            if magics or len(blob) != len(data):
                interesting += 1
                manifest.append({
                    'target': label,
                    'transform': name,
                    'out_len': len(blob),
                    'magics': json.dumps(magics, ensure_ascii=False),
                    'file': str(out_path.relative_to(out_dir)),
                })
                summary.append(f'  {name}: len={len(blob)} magics={magics}')

        if interesting == 0:
            summary.append('  no obvious decoded/magic-bearing outputs')
        summary.append('')

    import csv
    with (out_dir / 'probe_manifest.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['target','transform','out_len','magics','file'])
        w.writeheader()
        w.writerows(manifest)

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
