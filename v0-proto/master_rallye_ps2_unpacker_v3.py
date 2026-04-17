#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, hashlib, json, math, os, re, sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Tuple

SCENE_MARKERS = [b'<Scene>', b'</Scene>', b'<Egg', b'AI_List', b'Frontend/', b'ReplayTheatre', b'/MemoryCard/', b'RaceResults', b'gaRacePaceNoteAI', b'gaRaceLineAI', b'Image Bank Index', b'Type="Vector3"', b'Marker Pos']
CHUNK_MARKERS = [b'BX*Hd', b'BX91', b'BXA0', b'BXI1', b'bL1$', b'fTY2', b'g$rf', b'H!&', b'\xff\xfb']
CATEGORY_HINTS = {
    'frontend': [b'Frontend/', b'ReplayTheatre', b'/MemoryCard/', b'RaceResults', b'VehicleSelect', b'VehicleSetup', b'Trophy'],
    'race_ai': [b'gaRacePaceNoteAI', b'gaRaceLineAI', b'Marker Pos', b'Type="Vector3"', b'FinishArea', b'Checkpoint'],
    'progress_options_language': [b'Progress/', b'AudioOptions', b'Language/', b'MusicVolume', b'OpenedModes', b'WinStatus'],
}


def md5_bytes(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def find_all(data: bytes, pat: bytes) -> List[int]:
    out=[]; s=0
    while True:
        i=data.find(pat, s)
        if i==-1: break
        out.append(i); s=i+1
    return out


def entropy(b: bytes) -> float:
    if not b: return 0.0
    from collections import Counter
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


@dataclass
class RawSummary:
    name: str
    size: int
    md5: str
    sha256: str
    category_guess: str
    first_scene: int
    first_egg: int
    first_frontend: int
    first_replay: int
    first_pacenote: int
    first_marker_pos: int
    scene_count: int
    egg_count: int
    ai_list_count: int
    image_bank_count: int
    bx_chunk_count: int
    bx_first: int
    bx_last: int
    ff_fb_count: int
    likely_text_start: int
    likely_text_end: int
    likely_chunk_zone_start: int
    prefix_size: int
    suffix_size: int
    entropy_first64k: float
    entropy_last64k: float



def category_guess(data: bytes) -> str:
    scores={k:0 for k in CATEGORY_HINTS}
    for cat, pats in CATEGORY_HINTS.items():
        for p in pats:
            scores[cat] += data.count(p)
    best=max(scores.items(), key=lambda kv: kv[1])
    return best[0] if best[1] > 0 else 'unclassified'


def analyze_raw(path: Path) -> RawSummary:
    data=path.read_bytes()
    first = lambda p: data.find(p)
    bx_positions=[]
    for p in CHUNK_MARKERS[:-1]:
        bx_positions.extend(find_all(data,p))
    bx_positions=sorted(set(bx_positions))
    ff_positions=find_all(data, CHUNK_MARKERS[-1])

    text_candidates=[pos for pos in [first(b'<Scene>'), first(b'<Egg'), first(b'Frontend/'), first(b'gaRacePaceNoteAI')] if pos!=-1]
    likely_text_start=min(text_candidates) if text_candidates else -1

    # Heuristic end: last scene-ish / ai marker / frontend marker
    end_candidates=[]
    for p in [b'</Scene>', b'gaRacePaceNoteAI', b'ReplayTheatre', b'Image Bank Index', b'Type="Vector3"', b'Marker Pos']:
        offs=find_all(data,p)
        if offs:
            end_candidates.append(max(offs))
    likely_text_end=max(end_candidates) if end_candidates else -1

    # chunk zone start: first BX* marker if present, else first ff fb after halfway point
    chunk_zone_start=bx_positions[0] if bx_positions else -1
    if chunk_zone_start==-1 and ff_positions:
        half=len(data)//2
        post=[x for x in ff_positions if x>=half]
        if post:
            chunk_zone_start=post[0]
        else:
            chunk_zone_start=ff_positions[0]

    prefix_size = likely_text_start if likely_text_start!=-1 else -1
    suffix_size = len(data)-chunk_zone_start if chunk_zone_start!=-1 else 0

    return RawSummary(
        name=path.name,
        size=len(data),
        md5=md5_bytes(data),
        sha256=hashlib.sha256(data).hexdigest(),
        category_guess=category_guess(data),
        first_scene=first(b'<Scene>'),
        first_egg=first(b'<Egg'),
        first_frontend=first(b'Frontend/'),
        first_replay=first(b'ReplayTheatre'),
        first_pacenote=first(b'gaRacePaceNoteAI'),
        first_marker_pos=first(b'Marker Pos'),
        scene_count=len(find_all(data,b'<Scene>')),
        egg_count=len(find_all(data,b'<Egg')),
        ai_list_count=len(find_all(data,b'AI_List')),
        image_bank_count=len(find_all(data,b'Image Bank Index')),
        bx_chunk_count=len(bx_positions),
        bx_first=bx_positions[0] if bx_positions else -1,
        bx_last=bx_positions[-1] if bx_positions else -1,
        ff_fb_count=len(ff_positions),
        likely_text_start=likely_text_start,
        likely_text_end=likely_text_end,
        likely_chunk_zone_start=chunk_zone_start,
        prefix_size=prefix_size,
        suffix_size=suffix_size,
        entropy_first64k=round(entropy(data[:65536]), 4),
        entropy_last64k=round(entropy(data[-65536:]), 4),
    )


def carve_window(src: Path, offset: int, size: int, out_path: Path) -> None:
    with src.open('rb') as f:
        f.seek(offset)
        blob=f.read(size)
    out_path.write_bytes(blob)


def write_summary_table(rows: List[RawSummary], out_txt: Path) -> None:
    lines=[]
    lines.append('Master Rallye PS2 v3 raw analysis')
    lines.append('================================')
    for r in rows:
        lines.append(f"\n[{r.name}]")
        lines.append(f" size=0x{r.size:X} ({r.size})  category={r.category_guess}")
        lines.append(f" first_scene={hex(r.first_scene) if r.first_scene!=-1 else '-'}  first_egg={hex(r.first_egg) if r.first_egg!=-1 else '-'}  first_frontend={hex(r.first_frontend) if r.first_frontend!=-1 else '-'}")
        lines.append(f" first_replay={hex(r.first_replay) if r.first_replay!=-1 else '-'}  first_pacenote={hex(r.first_pacenote) if r.first_pacenote!=-1 else '-'}  first_marker_pos={hex(r.first_marker_pos) if r.first_marker_pos!=-1 else '-'}")
        lines.append(f" scene_count={r.scene_count} egg_count={r.egg_count} ai_list_count={r.ai_list_count} image_bank_count={r.image_bank_count}")
        lines.append(f" bx_chunk_count={r.bx_chunk_count} bx_first={hex(r.bx_first) if r.bx_first!=-1 else '-'} bx_last={hex(r.bx_last) if r.bx_last!=-1 else '-'} ff_fb_count={r.ff_fb_count}")
        lines.append(f" likely_text_start={hex(r.likely_text_start) if r.likely_text_start!=-1 else '-'} likely_text_end={hex(r.likely_text_end) if r.likely_text_end!=-1 else '-'} likely_chunk_zone_start={hex(r.likely_chunk_zone_start) if r.likely_chunk_zone_start!=-1 else '-'}")
        lines.append(f" prefix_size=0x{r.prefix_size:X} suffix_size=0x{r.suffix_size:X} entropy_first64k={r.entropy_first64k} entropy_last64k={r.entropy_last64k}")
    out_txt.write_text('\n'.join(lines), encoding='utf-8')


def main(argv: List[str]) -> int:
    ap=argparse.ArgumentParser(description='Master Rallye PS2 exploratory unpacker v3')
    sub=ap.add_subparsers(dest='cmd', required=True)

    p1=sub.add_parser('analyze-raw', help='Analyze one or more padded raw windows')
    p1.add_argument('inputs', nargs='+', type=Path)
    p1.add_argument('--out-dir', type=Path, default=Path('v3_raw_analysis'))

    p2=sub.add_parser('carve-window', help='Carve a raw window from a big file')
    p2.add_argument('src', type=Path)
    p2.add_argument('offset', type=lambda x: int(x,0))
    p2.add_argument('size', type=lambda x: int(x,0))
    p2.add_argument('out', type=Path)

    ns=ap.parse_args(argv)
    if ns.cmd=='carve-window':
        carve_window(ns.src, ns.offset, ns.size, ns.out)
        print(f'Wrote {ns.out}')
        return 0

    if ns.cmd=='analyze-raw':
        ns.out_dir.mkdir(parents=True, exist_ok=True)
        rows=[analyze_raw(p) for p in ns.inputs]
        with (ns.out_dir/'raw_summary.json').open('w', encoding='utf-8') as f:
            json.dump([asdict(r) for r in rows], f, ensure_ascii=False, indent=2)
        with (ns.out_dir/'raw_summary.csv').open('w', newline='', encoding='utf-8') as f:
            w=csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
            w.writeheader(); [w.writerow(asdict(r)) for r in rows]
        write_summary_table(rows, ns.out_dir/'raw_summary.txt')
        print((ns.out_dir/'raw_summary.txt').read_text(encoding='utf-8'))
        return 0
    return 1

if __name__=='__main__':
    raise SystemExit(main(sys.argv[1:]))
