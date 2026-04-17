#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

def read_bytes(p: Path) -> bytes:
    return p.read_bytes()

def write_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def common_prefix_len(blobs):
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[i] == blobs[0][i] for b in blobs[1:]):
        i += 1
    return i

def common_suffix_len(blobs):
    if not blobs:
        return 0
    n = min(len(b) for b in blobs)
    i = 0
    while i < n and all(b[-1-i] == blobs[0][-1-i] for b in blobs[1:]):
        i += 1
    return i

def u32_rows(data: bytes, endian: str):
    rows = []
    fmt = '<I' if endian == 'le' else '>I'
    for off in range(0, len(data) - 3, 4):
        u32 = struct.unpack_from(fmt, data, off)[0]
        rows.append({'off': off, 'u32': u32, 'hex': f'0x{u32:08X}'})
    return rows

def main():
    ap = argparse.ArgumentParser(description='BX v47 first artifact pass')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('build-first-artifact-pass')
    p.add_argument('v46_root', type=Path)
    p.add_argument('out_dir', type=Path)

    ns = ap.parse_args()
    if ns.cmd != 'build-first-artifact-pass':
        raise SystemExit(1)

    root: Path = ns.v46_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = []
    summary.append('BX v47 first artifact pass')
    summary.append('==========================')
    summary.append(f'v46_root: {root}')
    summary.append('')

    # --- rid 0A singleton track ---
    rid0a = root / 'rid_0A_singleton' / 'record.bin'
    if rid0a.exists():
        data = read_bytes(rid0a)
        sdir = out_dir / 'singleton_rid_0A'
        sdir.mkdir(parents=True, exist_ok=True)

        head16 = data[:16]
        head32 = data[:32]
        body = data[8:-16] if len(data) > 24 else data[8:]
        tail16 = data[-16:] if len(data) >= 16 else data

        write_bytes(sdir / 'record.bin', data)
        write_bytes(sdir / 'head16.bin', head16)
        write_bytes(sdir / 'head32.bin', head32)
        write_bytes(sdir / 'body.bin', body)
        write_bytes(sdir / 'tail16.bin', tail16)

        (sdir / 'record.hex.txt').write_text(data.hex(), encoding='utf-8')
        (sdir / 'head16.hex.txt').write_text(head16.hex(), encoding='utf-8')
        (sdir / 'head32.hex.txt').write_text(head32.hex(), encoding='utf-8')
        (sdir / 'body.hex.txt').write_text(body.hex(), encoding='utf-8')
        (sdir / 'tail16.hex.txt').write_text(tail16.hex(), encoding='utf-8')

        with (sdir / 'u32_le.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['off','u32','hex'])
            w.writeheader()
            w.writerows(u32_rows(data, 'le'))

        with (sdir / 'u32_be.csv').open('w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['off','u32','hex'])
            w.writeheader()
            w.writerows(u32_rows(data, 'be'))

        meta = {
            'len': len(data),
            'head4': data[:4].hex(),
            'head8': data[:8].hex(),
            'only_record_marker_at_start': data.find(b'\x00\x00\x01', 1) == -1,
        }
        (sdir / 'meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')

        summary.append(f'rid_0A_singleton: len={len(data)} head8={data[:8].hex()}')
        summary.append('  note: standalone candidate, no second 000001 marker inside')
        summary.append('')

    # --- rid 08 comparative track ---
    rid08 = root / 'rid_08_comparative'
    if rid08.exists():
        bodies = sorted(rid08.glob('*_body.bin'))
        blobs = [read_bytes(p) for p in bodies]
        names = [p.stem for p in bodies]
        cp = common_prefix_len(blobs)
        cs = common_suffix_len(blobs)

        cdir = out_dir / 'comparative_rid_08'
        cdir.mkdir(parents=True, exist_ok=True)

        if blobs:
            shared_head = blobs[0][:cp]
            shared_tail = blobs[0][len(blobs[0])-cs:] if cs > 0 else b''
            write_bytes(cdir / 'shared_head.bin', shared_head)
            (cdir / 'shared_head.hex.txt').write_text(shared_head.hex(), encoding='utf-8')
            if cs > 0:
                write_bytes(cdir / 'shared_tail.bin', shared_tail)
                (cdir / 'shared_tail.hex.txt').write_text(shared_tail.hex(), encoding='utf-8')

            rows = []
            for name, data in zip(names, blobs):
                body = data[cp: len(data)-cs if cs > 0 else len(data)]
                safe = name.replace('\\','_').replace('/','_')
                write_bytes(cdir / f'{safe}_body.bin', body)
                (cdir / f'{safe}_body.hex.txt').write_text(body.hex(), encoding='utf-8')
                rows.append({
                    'sample': name,
                    'full_len': len(data),
                    'shared_head_len': cp,
                    'body_len': len(body),
                    'shared_tail_len': cs,
                    'head8': data[:8].hex(),
                })

            with (cdir / 'body_manifest.csv').open('w', encoding='utf-8', newline='') as f:
                w = csv.DictWriter(f, fieldnames=['sample','full_len','shared_head_len','body_len','shared_tail_len','head8'])
                w.writeheader()
                w.writerows(rows)

            summary.append(f'rid_08_comparative: samples={len(blobs)} shared_head={cp} shared_tail={cs}')
            for r in rows:
                summary.append(f'  {r["sample"]}: len={r["full_len"]} body={r["body_len"]} head8={r["head8"]}')
            summary.append('  note: best comparative nested payload candidate')
            summary.append('')

    (out_dir / 'summary.txt').write_text('\n'.join(summary), encoding='utf-8')

if __name__ == '__main__':
    main()
