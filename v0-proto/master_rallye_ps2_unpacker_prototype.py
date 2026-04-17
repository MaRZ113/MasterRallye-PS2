#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

# Master Rallye PS2 exploratory unpacker / probe
# ------------------------------------------------
# Honest scope:
# - This is NOT yet a final full unpacker for TNG.PAK + TNG.000.
# - It is a research-grade prototype that helps reverse the format faster.
# - It can:
#   1) enumerate likely paths / fragments from TNG.PAK
#   2) dump metadata windows around them
#   3) scan TNG.000 for recurring chunk markers and XML-ish / scene-ish text blobs
#   4) carve windows around interesting offsets
#
# Why this exists:
# TNG.PAK is very likely a directory/index file and TNG.000 a data file.
# But the exact record structure is still unresolved: names appear to be stored
# in a prefix-compressed / trie-like / fragmentary form rather than as a simple
# flat table. This script is meant to accelerate that reverse-engineering.

ASCII_RE = re.compile(rb"[ -~]{4,}")
PATH_HINT_RE = re.compile(rb"(?:[A-Z0-9_\\/\- ]{2,}\.(?:XML|GXI|PSM|PSB|PSS|BSP|CFL)|\\TNG\\[A-Z0-9_\\/\- ]{4,}|[A-Z0-9_\\/\- ]+\\[A-Z0-9_\\/\- ]{2,})")
XMLISH_MARKERS = [
    b"<Egg",
    b"</Egg",
    b"AI_List",
    b"<Value Name=",
    b"Type=\"Vector3\"",
    b"Marker Pos",
    b"Marker Dir",
    b"2d Image Bank Index",
    b"gaRacePaceNoteAI",
    b"gaRaceSplitTimeAI",
    b"gaRaceLineAI",
    b"gaIContAIManager",
]
CHUNK_MARKERS = [b"BX*Hd", b"BX91", b"BXA0", b"BXI1", b"ELF"]


@dataclass
class PakString:
    offset: int
    text: str
    kind: str  # full_path / partial_path / fragment
    before_hex: str
    after_hex: str


@dataclass
class MarkerHit:
    marker: str
    offset: int
    context: str


def sanitize_filename(name: str) -> str:
    bad = '<>:"/\\|?*\x00'
    out = ''.join('_' if c in bad else c for c in name)
    out = out.strip(' .')
    return out or "unnamed"


def extract_ascii_strings(data: bytes, minlen: int = 4) -> Iterator[tuple[int, str]]:
    for m in ASCII_RE.finditer(data):
        s = m.group().decode("latin1", errors="ignore")
        if len(s) >= minlen:
            yield m.start(), s


def classify_pak_string(s: str) -> str:
    upper = s.upper()
    if any(ext in upper for ext in [".XML", ".GXI", ".PSM", ".PSB", ".PSS", ".BSP", ".CFL"]):
        if "\\" in s or "/" in s:
            return "full_path"
        return "fragment"
    if "\\" in s or "/" in s:
        return "partial_path"
    return "fragment"


def metadata_window(data: bytes, off: int, before: int = 20, after: int = 28) -> tuple[str, str]:
    b = data[max(0, off - before):off].hex()
    a = data[off:off + after].hex()
    return b, a


def scan_pak(pak_path: Path, out_json: Optional[Path], out_csv: Optional[Path], minlen: int = 4) -> list[PakString]:
    data = pak_path.read_bytes()
    hits: list[PakString] = []
    for off, s in extract_ascii_strings(data, minlen=minlen):
        if PATH_HINT_RE.search(s.encode("latin1", errors="ignore")):
            kind = classify_pak_string(s)
            before_hex, after_hex = metadata_window(data, off)
            hits.append(PakString(off, s, kind, before_hex, after_hex))

    # Deduplicate identical strings at same offset only; keep repeats elsewhere.
    hits.sort(key=lambda x: x.offset)

    if out_json:
        out_json.write_text(json.dumps([asdict(h) for h in hits], ensure_ascii=False, indent=2), encoding="utf-8")
    if out_csv:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["offset", "kind", "text", "before_hex", "after_hex"])
            w.writeheader()
            for h in hits:
                w.writerow(asdict(h))
    return hits


def find_all(data: bytes, needle: bytes) -> Iterator[int]:
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            return
        yield i
        start = i + 1


def scan_tng_markers(tng_path: Path, out_json: Optional[Path]) -> list[MarkerHit]:
    data = tng_path.read_bytes()
    hits: list[MarkerHit] = []
    for marker in CHUNK_MARKERS + XMLISH_MARKERS:
        for off in find_all(data, marker):
            lo = max(0, off - 32)
            hi = min(len(data), off + max(64, len(marker) + 32))
            ctx = data[lo:hi].decode("latin1", errors="replace")
            hits.append(MarkerHit(marker.decode("latin1", errors="replace"), off, ctx))
    hits.sort(key=lambda x: x.offset)
    if out_json:
        out_json.write_text(json.dumps([asdict(h) for h in hits], ensure_ascii=False, indent=2), encoding="utf-8")
    return hits


def carve_window(src: Path, offset: int, size: int, out_path: Path) -> None:
    with src.open("rb") as f:
        f.seek(offset)
        blob = f.read(size)
    out_path.write_bytes(blob)


def carve_xmlish_blocks(tng_path: Path, out_dir: Path, window_before: int = 256, window_after: int = 8192) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = tng_path.read_bytes()
    anchors = []
    for marker in XMLISH_MARKERS:
        anchors.extend(find_all(data, marker))
    anchors = sorted(set(anchors))

    # Merge nearby anchors into clusters.
    clusters: list[tuple[int, int]] = []
    for off in anchors:
        start = max(0, off - window_before)
        end = min(len(data), off + window_after)
        if clusters and start <= clusters[-1][1] + 2048:
            clusters[-1] = (clusters[-1][0], max(clusters[-1][1], end))
        else:
            clusters.append((start, end))

    out_files: list[Path] = []
    for i, (start, end) in enumerate(clusters):
        blob = data[start:end]
        p = out_dir / f"xmlish_{i:04d}_0x{start:X}-0x{end:X}.bin"
        p.write_bytes(blob)
        # Also dump a text view.
        txt = blob.decode("latin1", errors="replace")
        (out_dir / f"xmlish_{i:04d}_0x{start:X}-0x{end:X}.txt").write_text(txt, encoding="utf-8", errors="replace")
        out_files.append(p)
    return out_files


def dump_summary(pak_hits: list[PakString], marker_hits: list[MarkerHit]) -> str:
    full_paths = sum(1 for h in pak_hits if h.kind == "full_path")
    partial = sum(1 for h in pak_hits if h.kind == "partial_path")
    frags = sum(1 for h in pak_hits if h.kind == "fragment")
    marker_count = {}
    for h in marker_hits:
        marker_count[h.marker] = marker_count.get(h.marker, 0) + 1
    lines = []
    lines.append("Master Rallye PS2 prototype summary")
    lines.append("================================")
    lines.append(f"PAK strings: total={len(pak_hits)} full_path={full_paths} partial_path={partial} fragment={frags}")
    lines.append("Top PAK examples:")
    for h in pak_hits[:20]:
        lines.append(f"  0x{h.offset:X} [{h.kind}] {h.text}")
    lines.append("")
    lines.append("TNG marker hits:")
    for marker, count in sorted(marker_count.items(), key=lambda kv: (kv[0])):
        lines.append(f"  {marker}: {count}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Master Rallye PS2 exploratory unpacker / probe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_pak = sub.add_parser("scan-pak", help="Extract likely path strings / fragments from TNG.PAK")
    ap_pak.add_argument("pak", type=Path)
    ap_pak.add_argument("--json", type=Path)
    ap_pak.add_argument("--csv", type=Path)
    ap_pak.add_argument("--minlen", type=int, default=4)

    ap_tng = sub.add_parser("scan-tng", help="Scan TNG.000 for chunk markers and XML-ish markers")
    ap_tng.add_argument("tng", type=Path)
    ap_tng.add_argument("--json", type=Path)

    ap_carve = sub.add_parser("carve-window", help="Carve a byte window from a file")
    ap_carve.add_argument("src", type=Path)
    ap_carve.add_argument("offset", type=lambda x: int(x, 0))
    ap_carve.add_argument("size", type=lambda x: int(x, 0))
    ap_carve.add_argument("out", type=Path)

    ap_xml = sub.add_parser("carve-xmlish", help="Carve XML-ish / scene-ish clusters from TNG.000")
    ap_xml.add_argument("tng", type=Path)
    ap_xml.add_argument("out_dir", type=Path)

    ap_all = sub.add_parser("full-pass", help="Run PAK scan + TNG scan + xml-ish carving")
    ap_all.add_argument("pak", type=Path)
    ap_all.add_argument("tng", type=Path)
    ap_all.add_argument("out_dir", type=Path)

    ns = ap.parse_args(argv)

    if ns.cmd == "scan-pak":
        hits = scan_pak(ns.pak, ns.json, ns.csv, ns.minlen)
        print(f"Found {len(hits)} likely PAK strings/fragments")
        for h in hits[:40]:
            print(f"0x{h.offset:06X} [{h.kind:12}] {h.text}")
        return 0

    if ns.cmd == "scan-tng":
        hits = scan_tng_markers(ns.tng, ns.json)
        print(f"Found {len(hits)} marker hits")
        for h in hits[:40]:
            print(f"0x{h.offset:08X} {h.marker}")
        return 0

    if ns.cmd == "carve-window":
        carve_window(ns.src, ns.offset, ns.size, ns.out)
        print(f"Wrote {ns.out}")
        return 0

    if ns.cmd == "carve-xmlish":
        files = carve_xmlish_blocks(ns.tng, ns.out_dir)
        print(f"Wrote {len(files)} binary clusters (+ text views) into {ns.out_dir}")
        return 0

    if ns.cmd == "full-pass":
        ns.out_dir.mkdir(parents=True, exist_ok=True)
        pak_json = ns.out_dir / "pak_strings.json"
        pak_csv = ns.out_dir / "pak_strings.csv"
        tng_json = ns.out_dir / "tng_markers.json"
        xml_dir = ns.out_dir / "xmlish"

        pak_hits = scan_pak(ns.pak, pak_json, pak_csv)
        marker_hits = scan_tng_markers(ns.tng, tng_json)
        carve_xmlish_blocks(ns.tng, xml_dir)

        summary = dump_summary(pak_hits, marker_hits)
        (ns.out_dir / "summary.txt").write_text(summary, encoding="utf-8")
        print(summary)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
