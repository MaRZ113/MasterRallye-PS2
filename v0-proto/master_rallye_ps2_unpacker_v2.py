#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

ASCII_RE = re.compile(rb"[ -~]{4,}")
PATH_HINT_RE = re.compile(rb"(?:[A-Z0-9_\\/\- ]{2,}\.(?:XML|GXI|PSM|PSB|PSS|BSP|CFL)|\\TNG\\[A-Z0-9_\\/\- ]{4,}|[A-Z0-9_\\/\- ]+\\[A-Z0-9_\\/\- ]{2,})")
XMLISH_MARKERS = [
    b"<Egg", b"</Egg", b"AI_List", b"<Value Name=", b'Type="Vector3"',
    b"Marker Pos", b"Marker Dir", b"2d Image Bank Index", b"gaRacePaceNoteAI",
    b"gaRaceLineAI", b"gaIContAIManager", b"ReplayTheatre/", b"Frontend/",
]
CHUNK_MARKERS = [b"BX*Hd", b"BX91", b"BXA0", b"BXI1", b"ELF"]

CATEGORY_KEYWORDS = {
    "frontend": [
        "Frontend/", "ReplayTheatre/", "/MemoryCard/", "/VehicleSelect/", "/VehicleSetup/",
        "RaceResults", "Trophy", "CupSelect", "RaceSelect", "MainMenu", "Title",
    ],
    "progress_options_language": [
        "Progress/", "AudioOptions", "Language/", "Challenge/", "QuickRace",
        "SaveOptions", "OpenedModes", "WinStatus", "MusicVolume", "ControllerOptions",
    ],
    "race_ai": [
        "gaRacePaceNoteAI", "gaRaceLineAI", "gaIContAIManager", "Marker Pos", "Marker Dir",
        "Checkpoint", "SplitTime", "RaceTimer", "FinishArea", "PaceNote", "RaceLine",
    ],
    "course_objects": [
        "Waterfall", "BirdManager", "clouds", "sky/fog color", "misc\\objects",
        "gaAnimals_", "gaAiCloudSetUp", "Forest", "Produces tyre tracks", "Casts a shadow",
    ],
}

SUMMARY_TERMS = [
    "ReplayTheatre/", "Frontend/RaceResults/", "/MemoryCard/", "/VehicleSelect/",
    "Frontend/VehicleSetup/Player", "Frontend/Trophy", "CupSelect", "RaceSelect",
    "gaRacePaceNoteAI", "gaRaceLineAI", "gaIContAIManager", "Marker Pos", "Marker Dir",
]

@dataclass
class PakString:
    offset: int
    text: str
    kind: str
    before_hex: str
    after_hex: str

@dataclass
class XmlishRecord:
    name: str
    start: int
    end: int
    size: int
    md5: str
    duplicate_group: str
    duplicate_count: int
    mirror_of: Optional[str]
    mirror_delta: Optional[int]
    category: str
    category_scores: dict
    summary_hits: dict
    top_terms: list[str]


def extract_ascii_strings(data: bytes, minlen: int = 4):
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


def scan_pak(pak_path: Path, out_json: Optional[Path], out_csv: Optional[Path], minlen: int = 4):
    data = pak_path.read_bytes()
    hits = []
    for off, s in extract_ascii_strings(data, minlen=minlen):
        if PATH_HINT_RE.search(s.encode("latin1", errors="ignore")):
            before = data[max(0, off - 20):off].hex()
            after = data[off:off + 28].hex()
            hits.append(PakString(off, s, classify_pak_string(s), before, after))
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


def find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            return
        yield i
        start = i + 1


def scan_tng_markers(tng_path: Path, out_json: Optional[Path]):
    data = tng_path.read_bytes()
    hits = []
    for marker in CHUNK_MARKERS + XMLISH_MARKERS:
        for off in find_all(data, marker):
            hits.append({"marker": marker.decode("latin1", errors="replace"), "offset": off})
    hits.sort(key=lambda x: x["offset"])
    if out_json:
        out_json.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8")
    return hits


def carve_xmlish_blocks(tng_path: Path, out_dir: Path, window_before: int = 256, window_after: int = 8192):
    out_dir.mkdir(parents=True, exist_ok=True)
    data = tng_path.read_bytes()
    anchors = []
    for marker in XMLISH_MARKERS:
        anchors.extend(find_all(data, marker))
    anchors = sorted(set(anchors))
    clusters = []
    for off in anchors:
        start = max(0, off - window_before)
        end = min(len(data), off + window_after)
        if clusters and start <= clusters[-1][1] + 2048:
            clusters[-1] = (clusters[-1][0], max(clusters[-1][1], end))
        else:
            clusters.append((start, end))
    out_files = []
    for i, (start, end) in enumerate(clusters):
        blob = data[start:end]
        stem = f"xmlish_{i:04d}_0x{start:X}-0x{end:X}"
        (out_dir / f"{stem}.bin").write_bytes(blob)
        (out_dir / f"{stem}.txt").write_text(blob.decode("latin1", errors="replace"), encoding="utf-8", errors="replace")
        out_files.append(out_dir / f"{stem}.txt")
    return out_files


def parse_offsets_from_name(name: str):
    m = re.search(r"0x([0-9A-F]+)-0x([0-9A-F]+)", name)
    if not m:
        raise ValueError(f"cannot parse offsets from {name}")
    return int(m.group(1), 16), int(m.group(2), 16)


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def classify_xmlish_text(text: str):
    scores = {k: 0 for k in CATEGORY_KEYWORDS}
    for cat, kws in CATEGORY_KEYWORDS.items():
        for kw in kws:
            scores[cat] += text.count(kw)
    category = max(scores, key=scores.get)
    if all(v == 0 for v in scores.values()):
        category = "unclassified"
    return category, scores


def summary_hits(text: str):
    hits = {term: text.count(term) for term in SUMMARY_TERMS if text.count(term)}
    return dict(sorted(hits.items(), key=lambda kv: (-kv[1], kv[0])))


def top_terms_from_text(text: str, n: int = 12):
    terms = []
    for term in SUMMARY_TERMS:
        c = text.count(term)
        if c:
            terms.append((term, c))
    return [f"{t}:{c}" for t, c in sorted(terms, key=lambda kv: (-kv[1], kv[0]))[:n]]


def analyze_xmlish_dir(xmlish_dir: Path, out_dir: Optional[Path] = None):
    txt_files = sorted(xmlish_dir.glob("*.txt"))
    by_hash: dict[str, list[Path]] = defaultdict(list)
    for f in txt_files:
        by_hash[md5_file(f)].append(f)

    # duplicate groups
    hash_to_group = {}
    for idx, h in enumerate(sorted(by_hash.keys())):
        hash_to_group[h] = f"grp_{idx:03d}"

    # common mirror delta among exact duplicates
    delta_counter = Counter()
    for arr in by_hash.values():
        if len(arr) >= 2:
            arr = sorted(arr, key=lambda p: parse_offsets_from_name(p.name)[0])
            base_start, _ = parse_offsets_from_name(arr[0].name)
            for other in arr[1:]:
                other_start, _ = parse_offsets_from_name(other.name)
                delta_counter[other_start - base_start] += 1
    common_mirror_delta = delta_counter.most_common(1)[0][0] if delta_counter else None

    records: list[XmlishRecord] = []
    for f in txt_files:
        start, end = parse_offsets_from_name(f.name)
        txt = f.read_text(encoding="utf-8", errors="ignore")
        h = md5_file(f)
        category, scores = classify_xmlish_text(txt)
        s_hits = summary_hits(txt)
        dup_list = sorted(by_hash[h], key=lambda p: parse_offsets_from_name(p.name)[0])
        mirror_of = None
        mirror_delta = None
        if len(dup_list) > 1:
            base = dup_list[0]
            if f != base:
                base_start, _ = parse_offsets_from_name(base.name)
                mirror_of = base.name
                mirror_delta = start - base_start
        records.append(XmlishRecord(
            name=f.name,
            start=start,
            end=end,
            size=end - start,
            md5=h,
            duplicate_group=hash_to_group[h],
            duplicate_count=len(dup_list),
            mirror_of=mirror_of,
            mirror_delta=mirror_delta,
            category=category,
            category_scores=scores,
            summary_hits=s_hits,
            top_terms=top_terms_from_text(txt),
        ))

    records.sort(key=lambda r: r.start)

    result = {
        "xmlish_total": len(records),
        "xmlish_unique_hashes": len(by_hash),
        "duplicate_groups": sum(1 for v in by_hash.values() if len(v) > 1),
        "common_mirror_delta": common_mirror_delta,
        "records": [asdict(r) for r in records],
    }

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "xmlish_manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        with (out_dir / "xmlish_manifest.csv").open("w", newline="", encoding="utf-8") as f:
            fields = [
                "name", "start", "end", "size", "md5", "duplicate_group", "duplicate_count",
                "mirror_of", "mirror_delta", "category", "top_terms"
            ]
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in records:
                row = {
                    "name": r.name,
                    "start": hex(r.start),
                    "end": hex(r.end),
                    "size": r.size,
                    "md5": r.md5,
                    "duplicate_group": r.duplicate_group,
                    "duplicate_count": r.duplicate_count,
                    "mirror_of": r.mirror_of or "",
                    "mirror_delta": hex(r.mirror_delta) if r.mirror_delta is not None else "",
                    "category": r.category,
                    "top_terms": " | ".join(r.top_terms),
                }
                w.writerow(row)

        # family folders with canonical copies only
        family_dir = out_dir / "xmlish_families"
        family_dir.mkdir(exist_ok=True)
        for cat in sorted({r.category for r in records}):
            (family_dir / cat).mkdir(exist_ok=True)
        for r in records:
            if r.mirror_of:
                continue  # only canonical copy per duplicate group
            src_txt = xmlish_dir / r.name
            src_bin = xmlish_dir / r.name.replace('.txt', '.bin')
            dst_stem = f"{r.duplicate_group}__0x{r.start:X}-0x{r.end:X}__{r.category}"
            shutil.copy2(src_txt, family_dir / r.category / f"{dst_stem}.txt")
            if src_bin.exists():
                shutil.copy2(src_bin, family_dir / r.category / f"{dst_stem}.bin")

        # concise human summary
        cat_count = Counter(r.category for r in records)
        lines = []
        lines.append("Master Rallye PS2 xmlish analysis")
        lines.append("================================")
        lines.append(f"xmlish total: {len(records)}")
        lines.append(f"unique content hashes: {len(by_hash)}")
        lines.append(f"duplicate groups: {sum(1 for v in by_hash.values() if len(v) > 1)}")
        lines.append(f"common mirror delta: {hex(common_mirror_delta) if common_mirror_delta is not None else 'n/a'}")
        lines.append("")
        lines.append("category counts:")
        for cat, count in sorted(cat_count.items()):
            lines.append(f"  {cat}: {count}")
        lines.append("")
        lines.append("top canonical clusters:")
        for r in [rr for rr in records if not rr.mirror_of][:12]:
            lines.append(f"  {r.name} | {r.category} | dup={r.duplicate_count} | terms={', '.join(r.top_terms[:6])}")
        (out_dir / "xmlish_summary_v2.txt").write_text("\n".join(lines), encoding="utf-8")

    return result


def full_pass(pak: Path, tng: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    scan_pak(pak, out_dir / "pak_strings.json", out_dir / "pak_strings.csv")
    scan_tng_markers(tng, out_dir / "tng_markers.json")
    xmlish_dir = out_dir / "xmlish"
    carve_xmlish_blocks(tng, xmlish_dir)
    analyze_xmlish_dir(xmlish_dir, out_dir)


def main():
    ap = argparse.ArgumentParser(description="Master Rallye PS2 unpacker v2 / xmlish analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("full-pass", help="Run pak scan + tng scan + xmlish carve + v2 analysis")
    p1.add_argument("pak", type=Path)
    p1.add_argument("tng", type=Path)
    p1.add_argument("out_dir", type=Path)

    p2 = sub.add_parser("analyze-pass", help="Analyze an existing out_dir/xmlish folder from a prior run")
    p2.add_argument("xmlish_dir", type=Path)
    p2.add_argument("out_dir", type=Path)

    args = ap.parse_args()
    if args.cmd == "full-pass":
        full_pass(args.pak, args.tng, args.out_dir)
        print(f"Wrote v2 pass into {args.out_dir}")
    elif args.cmd == "analyze-pass":
        analyze_xmlish_dir(args.xmlish_dir, args.out_dir)
        print(f"Wrote xmlish analysis into {args.out_dir}")

if __name__ == "__main__":
    main()
