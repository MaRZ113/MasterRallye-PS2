#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, json, math, os, re, struct, hashlib
from pathlib import Path
from collections import Counter, defaultdict
from statistics import median

RID_ROLE = {1:'header',2:'header',3:'header',4:'header',5:'descriptor',6:'descriptor',7:'descriptor',8:'data',9:'data',10:'data',11:'data',12:'data',13:'data',14:'data',15:'data',16:'terminal'}
FOCUS_DESCRIPTOR = [5,6,7]
FOCUS_HEADER = [1,2,3,4]
FOCUS_DATA = [8,9,10,12,13,14,15]
MAGICS = [b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'\x1f\x8b', b'BZh', b'PK\x03\x04', b'RIFF', b'OggS', b'\x7fELF']


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def find_files(root: Path):
    bins = list(root.rglob('rid_*.bin'))
    chains = defaultdict(dict)
    for fp in bins:
        m = re.search(r'chain_(\d+).*?rid_(\d+)_', str(fp).replace('\\','/'))
        if not m:
            continue
        chain = int(m.group(1))
        rid = int(m.group(2))
        chains[chain][rid] = fp
    return dict(sorted(chains.items()))


def stable_mask(blobs: list[bytes]):
    if not blobs:
        return '', 0
    maxlen = max(len(b) for b in blobs)
    out = []
    stable = 0
    for i in range(maxlen):
        vals = set(b[i] for b in blobs if i < len(b))
        if len(vals) == 1 and len([1 for b in blobs if i < len(b)]) == len(blobs):
            v = next(iter(vals))
            out.append(f'{v:02X}')
            stable += 1
        else:
            out.append('..')
    return ' '.join(out), stable


def scan_magics(data: bytes):
    hits = []
    for mg in MAGICS:
        off = data.find(mg)
        if off != -1:
            hits.append((off, mg.hex()))
    return hits


def mine_descriptor_values(desc: bytes, data_sizes: set[int]):
    hits = []
    n = len(desc)
    for w in (2,4):
        for endian in ('<','>'):
            fmt = endian + ('H' if w==2 else 'I')
            for off in range(0, n - w + 1):
                try:
                    val = struct.unpack_from(fmt, desc, off)[0]
                except struct.error:
                    continue
                if val in data_sizes and val != 0:
                    hits.append({'off':off,'width':w,'endian':'LE' if endian=='<' else 'BE','value':val})
    # dedup exact duplicates
    seen=set(); uniq=[]
    for h in hits:
        k=(h['off'],h['width'],h['endian'],h['value'])
        if k not in seen:
            seen.add(k); uniq.append(h)
    return uniq


def family_summary(name: str, root: Path):
    chains = find_files(root)
    out = {'family': name, 'root': str(root), 'chains': len(chains), 'rid': {}}
    for rid in range(1,17):
        blobs=[]
        for ch, m in chains.items():
            if rid in m:
                blobs.append(m[rid].read_bytes())
        if not blobs:
            continue
        mask, stable = stable_mask(blobs)
        out['rid'][rid] = {
            'count': len(blobs),
            'median_size': int(median(len(b) for b in blobs)),
            'avg_entropy': round(sum(entropy(b) for b in blobs)/len(blobs), 4),
            'stable_positions': stable,
            'stable_mask': mask,
            'magics': [scan_magics(blobs[0])],
        }
    return out, chains


def analyze(full_root: Path, variant_root: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    full_sum, full_chains = family_summary('full', full_root)
    var_sum, var_chains = family_summary('variant', variant_root)

    # per-chain descriptor mining against data sizes
    mine_rows=[]
    for fam_name, chains in [('full', full_chains), ('variant', var_chains)]:
        for chain_id, mapping in chains.items():
            data_sizes = {mapping[r].stat().st_size for r in mapping if RID_ROLE.get(r)=='data'}
            for rid in FOCUS_DESCRIPTOR:
                fp = mapping.get(rid)
                if not fp:
                    continue
                desc = fp.read_bytes()
                for hit in mine_descriptor_values(desc, data_sizes):
                    hit.update({'family': fam_name, 'chain': chain_id, 'rid': rid, 'file': fp.name})
                    mine_rows.append(hit)

    # aggregate candidate fields
    agg = defaultdict(lambda: {'hits':0,'families':set(),'chains':set(),'rids':set(),'values':Counter()})
    for r in mine_rows:
        key = (r['rid'], r['off'], r['width'], r['endian'])
        a = agg[key]
        a['hits'] += 1
        a['families'].add(r['family'])
        a['chains'].add(r['chain'])
        a['rids'].add(r['rid'])
        a['values'][r['value']] += 1

    rows=[]
    for (rid, off, width, endian), a in sorted(agg.items(), key=lambda kv:(kv[0][0], kv[0][1], kv[0][2], kv[0][3])):
        rows.append({
            'rid': rid,
            'off': off,
            'width': width,
            'endian': endian,
            'hits': a['hits'],
            'families': ','.join(sorted(a['families'])),
            'chains': len(a['chains']),
            'top_values': ';'.join(f'{v}:{c}' for v,c in a['values'].most_common(8)),
        })

    # summary text
    lines=[]
    lines.append('BX v16 header+descriptor mining')
    lines.append('================================')
    lines.append(f'full_root={full_root}')
    lines.append(f'variant_root={variant_root}')
    lines.append('')
    lines.append('Header candidates:')
    for rid in FOCUS_HEADER:
        fr = full_sum['rid'].get(rid)
        vr = var_sum['rid'].get(rid)
        if fr and vr:
            lines.append(f"rid {rid}: full_med={fr['median_size']} var_med={vr['median_size']} full_stable={fr['stable_positions']} var_stable={vr['stable_positions']}")
    lines.append('')
    lines.append('Descriptor size-field candidates (sorted by hits):')
    top = sorted(rows, key=lambda r:(-r['hits'], r['rid'], r['off']))[:30]
    for r in top:
        lines.append(f"rid {r['rid']} off=0x{r['off']:X} w={r['width']} {r['endian']} hits={r['hits']} families={r['families']} top={r['top_values']}")
    lines.append('')
    lines.append('Suggested next decode focus:')
    lines.append('1) rid 01 byte-level header field split')
    lines.append('2) rid 05-07 candidate size/selector fields above')
    lines.append('3) payload rid 09,10,13,15 as first extraction targets')

    (out_dir/'summary.txt').write_text('\n'.join(lines), encoding='utf-8')
    (out_dir/'full_family_summary.json').write_text(json.dumps(full_sum, indent=2), encoding='utf-8')
    (out_dir/'variant_family_summary.json').write_text(json.dumps(var_sum, indent=2), encoding='utf-8')
    with (out_dir/'descriptor_field_candidates.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['rid','off','width','endian','hits','families','chains','top_values'])
        w.writeheader(); w.writerows(rows)
    with (out_dir/'descriptor_field_hits.json').open('w', encoding='utf-8') as f:
        json.dump(mine_rows, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    a = sp.add_parser('analyze-unpacks')
    a.add_argument('full_root', type=Path)
    a.add_argument('variant_root', type=Path)
    a.add_argument('out_dir', type=Path)
    ns = ap.parse_args()
    if ns.cmd == 'analyze-unpacks':
        analyze(ns.full_root, ns.variant_root, ns.out_dir)

if __name__ == '__main__':
    main()
