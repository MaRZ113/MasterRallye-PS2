#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

DESCRIPTOR_RIDS = [4, 5, 6, 7]
PAYLOAD_RIDS = [9, 10, 13, 15]

def load_schema(root: Path, rid: int, bucket: str) -> dict:
    p = root / f"rid_{rid:02d}_{bucket}" / "schema.json"
    if not p.exists():
        raise FileNotFoundError(p)
    return json.loads(p.read_text(encoding="utf-8"))

def seg_stats(schema: dict) -> dict:
    stats = {
        "shared_segments": 0,
        "replace_segments": 0,
        "insert_segments": 0,
        "delete_segments": 0,
        "shared_bytes": 0,
        "replace_full_bytes": 0,
        "replace_variant_bytes": 0,
        "insert_variant_bytes": 0,
        "delete_full_bytes": 0,
    }
    for seg in schema.get("segments", []):
        kind = seg.get("kind")
        if kind == "shared":
            stats["shared_segments"] += 1
            stats["shared_bytes"] += int(seg.get("len", 0))
        elif kind == "replace":
            stats["replace_segments"] += 1
            stats["replace_full_bytes"] += int(seg.get("full_len", 0))
            stats["replace_variant_bytes"] += int(seg.get("variant_len", 0))
        elif kind == "insert":
            stats["insert_segments"] += 1
            stats["insert_variant_bytes"] += int(seg.get("variant_len", 0))
        elif kind == "delete":
            stats["delete_segments"] += 1
            stats["delete_full_bytes"] += int(seg.get("full_len", 0))
    return stats

def main():
    ap = argparse.ArgumentParser(description="BX v26 descriptor->payload mapping pass")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("map-seed")
    p.add_argument("seed_root", type=Path)
    p.add_argument("out_dir", type=Path)

    ns = ap.parse_args()
    if ns.cmd != "map-seed":
        raise SystemExit(1)

    seed_root: Path = ns.seed_root
    out_dir: Path = ns.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    desc_rows: List[dict] = []
    payload_rows: List[dict] = []

    for rid in DESCRIPTOR_RIDS:
        sch = load_schema(seed_root, rid, "descriptor")
        row = {
            "rid": rid,
            "bucket": "descriptor",
            "full_len": sch["full_len"],
            "variant_len": sch["variant_len"],
            "delta_len": sch["full_len"] - sch["variant_len"],
            "equal_ratio": sch["equal_ratio"],
            "change_count": sch["change_count"],
        }
        row.update(seg_stats(sch))
        desc_rows.append(row)

    for rid in PAYLOAD_RIDS:
        sch = load_schema(seed_root, rid, "payload")
        row = {
            "rid": rid,
            "bucket": "payload",
            "full_len": sch["full_len"],
            "variant_len": sch["variant_len"],
            "delta_len": sch["full_len"] - sch["variant_len"],
            "equal_ratio": sch["equal_ratio"],
            "change_count": sch["change_count"],
        }
        row.update(seg_stats(sch))
        payload_rows.append(row)

    # Hypothesis matrix: compare sign/magnitude of descriptor deltas to payload deltas
    matrix_rows: List[dict] = []
    for d in desc_rows:
        for pld in payload_rows:
            sign_match = (d["delta_len"] == 0 and pld["delta_len"] == 0) or (
                d["delta_len"] > 0 and pld["delta_len"] > 0
            ) or (
                d["delta_len"] < 0 and pld["delta_len"] < 0
            )
            # simple closeness heuristic
            gap = abs(abs(int(d["delta_len"])) - abs(int(pld["delta_len"])))
            magnitude_ratio = (
                abs(int(pld["delta_len"])) / abs(int(d["delta_len"]))
                if int(d["delta_len"]) != 0 else None
            )
            matrix_rows.append({
                "descriptor_rid": d["rid"],
                "payload_rid": pld["rid"],
                "descriptor_delta_len": d["delta_len"],
                "payload_delta_len": pld["delta_len"],
                "same_delta_sign": sign_match,
                "abs_gap": gap,
                "magnitude_ratio": magnitude_ratio,
                "descriptor_equal_ratio": d["equal_ratio"],
                "payload_equal_ratio": pld["equal_ratio"],
                "descriptor_change_count": d["change_count"],
                "payload_change_count": pld["change_count"],
            })

    # Choose top candidates for first manual decode
    # Bias toward low equal_ratio + strong delta in descriptors and payloads
    ranked_payload = sorted(
        payload_rows,
        key=lambda r: (abs(int(r["delta_len"])), -float(r["equal_ratio"])),
        reverse=True
    )
    ranked_desc = sorted(
        desc_rows,
        key=lambda r: (abs(int(r["delta_len"])), -float(r["equal_ratio"])),
        reverse=True
    )

    # Write csv files
    with (out_dir / "descriptor_summary.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(desc_rows[0].keys()))
        w.writeheader()
        w.writerows(desc_rows)

    with (out_dir / "payload_summary.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(payload_rows[0].keys()))
        w.writeheader()
        w.writerows(payload_rows)

    with (out_dir / "descriptor_payload_matrix.csv").open("w", encoding="utf-8", newline="") as f:
        fieldnames = list(matrix_rows[0].keys()) if matrix_rows else []
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(matrix_rows)

    summary_lines = []
    summary_lines.append("BX v26 descriptor->payload seed map")
    summary_lines.append("===================================")
    summary_lines.append(f"seed_root: {seed_root}")
    summary_lines.append("")
    summary_lines.append("Descriptor ranking:")
    for r in ranked_desc:
        summary_lines.append(
            f"rid {r['rid']:02d}: delta={r['delta_len']} equal_ratio={r['equal_ratio']:.4f} "
            f"changes={r['change_count']} shared={r['shared_bytes']} "
            f"replaceF={r['replace_full_bytes']} replaceV={r['replace_variant_bytes']} "
            f"insertV={r['insert_variant_bytes']} deleteF={r['delete_full_bytes']}"
        )
    summary_lines.append("")
    summary_lines.append("Payload ranking:")
    for r in ranked_payload:
        summary_lines.append(
            f"rid {r['rid']:02d}: delta={r['delta_len']} equal_ratio={r['equal_ratio']:.4f} "
            f"changes={r['change_count']} shared={r['shared_bytes']} "
            f"replaceF={r['replace_full_bytes']} replaceV={r['replace_variant_bytes']} "
            f"insertV={r['insert_variant_bytes']} deleteF={r['delete_full_bytes']}"
        )
    summary_lines.append("")
    summary_lines.append("Suggested first manual decode targets:")
    if ranked_desc:
        summary_lines.append(f"1) descriptor rid {ranked_desc[0]['rid']:02d}")
    if len(ranked_desc) > 1:
        summary_lines.append(f"2) descriptor rid {ranked_desc[1]['rid']:02d}")
    if ranked_payload:
        summary_lines.append(f"3) payload rid {ranked_payload[0]['rid']:02d}")
    if len(ranked_payload) > 1:
        summary_lines.append(f"4) payload rid {ranked_payload[1]['rid']:02d}")

    (out_dir / "summary.txt").write_text("\n".join(summary_lines), encoding="utf-8")

    meta = {
        "descriptors": desc_rows,
        "payloads": payload_rows,
        "ranked_descriptor_rids": [r["rid"] for r in ranked_desc],
        "ranked_payload_rids": [r["rid"] for r in ranked_payload],
    }
    (out_dir / "analysis.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

if __name__ == "__main__":
    main()
