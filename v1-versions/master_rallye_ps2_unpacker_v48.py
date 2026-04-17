#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import struct
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_text(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding='utf-8')

def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off+width]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{off:04X}  {hexs:<{width*3}}  {asci}')
    return '\n'.join(lines)

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def scan_words(data: bytes):
    rows = []
    for off in range(0, len(data)-1, 2):
        u16le = struct.unpack_from('<H', data, off)[0]
        u16be = struct.unpack_from('>H', data, off)[0]
        rows.append({'off': off, 'size': 2, 'u16_le': u16le, 'u16_be': u16be})
    for off in range(0, len(data)-3, 4):
        u32le = struct.unpack_from('<I', data, off)[0]
        u32be = struct.unpack_from('>I', data, off)[0]
        rows.append({'off': off, 'size': 4, 'u32_le': u32le, 'u32_be': u32be})
    return rows

def main():
    ap = argparse.ArgumentParser(description='BX v48 singleton rid0A decode prep')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('probe-rid0a')
    p.add_argument('v47_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'probe-rid0a':
        raise SystemExit(1)

    root: Path = ns.v47_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    sdir = root / 'singleton_rid_0A'
    record = read_bytes(sdir / 'record.bin')
    head16 = record[:16]
    head32 = record[:32]
    body = record[8:-16] if len(record) > 24 else record[8:]
    tail16 = record[-16:] if len(record) >= 16 else record

    # Primary splits
    (out_dir / 'record.bin').write_bytes(record)
    (out_dir / 'head16.bin').write_bytes(head16)
    (out_dir / 'head32.bin').write_bytes(head32)
    (out_dir / 'body.bin').write_bytes(body)
    (out_dir / 'tail16.bin').write_bytes(tail16)

    write_text(out_dir / 'record.hexdump.txt', hexdump(record))
    write_text(out_dir / 'body.hexdump.txt', hexdump(body))

    # Word scans
    rows = scan_words(record)
    with (out_dir / 'word_scan.csv').open('w', encoding='utf-8', newline='') as f:
        fieldnames = ['off','size','u16_le','u16_be','u32_le','u32_be']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({
                'off': r.get('off'),
                'size': r.get('size'),
                'u16_le': r.get('u16_le',''),
                'u16_be': r.get('u16_be',''),
                'u32_le': r.get('u32_le',''),
                'u32_be': r.get('u32_be',''),
            })

    # Candidate fields: small values that could be lengths/offsets
    cand = []
    rec_len = len(record)
    for off in range(0, len(record)-3, 4):
        u32le = struct.unpack_from('<I', record, off)[0]
        u32be = struct.unpack_from('>I', record, off)[0]
        if 0 < u32le <= rec_len:
            cand.append({'off': off, 'endian': 'le', 'u32': u32le})
        if 0 < u32be <= rec_len:
            cand.append({'off': off, 'endian': 'be', 'u32': u32be})

    with (out_dir / 'candidate_small_fields.csv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['off','endian','u32'])
        w.writeheader()
        w.writerows(cand)

    meta = {
        'len': len(record),
        'head4': record[:4].hex(),
        'head8': record[:8].hex(),
        'head16': head16.hex(),
        'tail16': tail16.hex(),
        'body_len': len(body),
        'entropy_record': entropy(record),
        'entropy_body': entropy(body),
        'has_second_record_marker': record.find(b'\x00\x00\x01', 1) != -1,
    }
    (out_dir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

    summary = []
    summary.append('BX v48 singleton rid0A decode prep')
    summary.append('=================================')
    summary.append(f'record_len: {len(record)}')
    summary.append(f'head8: {record[:8].hex()}')
    summary.append(f'head16: {head16.hex()}')
    summary.append(f'tail16: {tail16.hex()}')
    summary.append(f'body_len: {len(body)}')
    summary.append(f'entropy_record: {entropy(record):.4f}')
    summary.append(f'entropy_body: {entropy(body):.4f}')
    summary.append(f'has_second_record_marker: {meta["has_second_record_marker"]}')
    summary.append('')
    summary.append('Candidate small u32 fields:')
    for row in cand[:20]:
        summary.append(f'  off={row["off"]} endian={row["endian"]} value={row["u32"]}')
    write_text(out_dir / 'summary.txt', '\n'.join(summary))

if __name__ == '__main__':
    main()
