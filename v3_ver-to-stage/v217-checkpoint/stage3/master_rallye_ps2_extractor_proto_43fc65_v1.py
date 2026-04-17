
#!/usr/bin/env python3
import argparse, csv, mmap, os, shutil, struct, subprocess, json, hashlib
from collections import defaultdict

PACK = b"\x00\x00\x01\xBA"
END  = b"\x00\x00\x01\xB9"
TOP_POSITIONS = [0x6C, 0x88, 0x100, 0x154]
MAX_BACK = 0x20000
MAX_FWD = 0x1000000
MAX_SIZE = 0x2000000
RECORD_LEN = 507

def u32le(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def find_prev(mm, off, pat, max_back):
    s = max(0, off - max_back)
    return mm.rfind(pat, s, off + 1)

def find_next(mm, off, pat, max_fwd):
    e = min(len(mm), off + max_fwd)
    return mm.find(pat, off, e)

def ffprobe_summary(path):
    proc = subprocess.run(
        ["ffprobe", "-v", "error", "-print_format", "json", "-show_streams", "-show_format", path],
        capture_output=True, text=True
    )
    if proc.returncode != 0:
        return {"ok": False}
    try:
        j = json.loads(proc.stdout)
    except Exception:
        return {"ok": False}
    streams = j.get("streams", [])
    fmt = j.get("format", {})
    return {
        "ok": True,
        "format_name": fmt.get("format_name"),
        "duration": fmt.get("duration"),
        "stream_count": len(streams),
        "stream_types": ",".join(sorted(set(s.get("codec_type","?") for s in streams))),
    }

def main():
    ap = argparse.ArgumentParser(description="Master Rallye PS2 43fc65 branch-aware PS/PSS extractor prototype")
    ap.add_argument("tng", help="Path to canonical TNG.000")
    ap.add_argument("--feature-table", required=True, help="43fc65 feature table CSV")
    ap.add_argument("--outdir", required=True, help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    exports_dir = os.path.join(args.outdir, "exports")
    os.makedirs(exports_dir, exist_ok=True)

    import pandas as pd
    ft = pd.read_csv(args.feature_table)

    with open(args.tng, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        clusters = defaultdict(list)

        for rec_off in ft["off"].tolist():
            rec_off = int(rec_off)
            for pos in TOP_POSITIONS:
                val = u32le(mm, rec_off + pos)
                if 0 < val < len(mm):
                    start = find_prev(mm, val, PACK, MAX_BACK)
                    end = find_next(mm, val, END, MAX_FWD)
                    if start != -1 and end != -1 and end > start and (end - start) < MAX_SIZE:
                        clusters[(start, end)].append((rec_off, pos, val))

        cluster_rows = []
        for idx, ((start, end), refs) in enumerate(sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True), start=1):
            fn = f"cluster_{idx:02d}_{start:08X}_{end:08X}.pss"
            path = os.path.join(exports_dir, fn)
            with open(path, "wb") as out:
                out.write(mm[start:end+4])
            fp = ffprobe_summary(path)
            cluster_rows.append({
                "cluster_id": idx,
                "file": fn,
                "start": start,
                "end": end,
                "size": end - start + 4,
                "support": len(refs),
                "unique_records": len(set(r[0] for r in refs)),
                "unique_positions": len(set(r[1] for r in refs)),
                **fp,
            })

        cluster_csv = os.path.join(args.outdir, "stream_clusters.csv")
        with open(cluster_csv, "w", newline="") as fcsv:
            w = csv.DictWriter(fcsv, fieldnames=list(cluster_rows[0].keys()) if cluster_rows else ["cluster_id"])
            w.writeheader()
            for row in cluster_rows:
                w.writerow(row)

        # Greedy per-record assignment to strongest validated cluster
        valid_map = {(r["start"], r["end"]): r for r in cluster_rows if r.get("ok")}
        assign_rows = []
        for rec_off in ft["off"].tolist():
            rec_off = int(rec_off)
            best = None
            for pos in TOP_POSITIONS:
                val = u32le(mm, rec_off + pos)
                if 0 < val < len(mm):
                    start = find_prev(mm, val, PACK, MAX_BACK)
                    end = find_next(mm, val, END, MAX_FWD)
                    key = (start, end)
                    if key in valid_map:
                        meta = valid_map[key]
                        score = meta["support"] * 10 + meta["unique_positions"] * 2 - ((val - start) / 1024.0)
                        cand = (score, rec_off, pos, val, start, end, meta["cluster_id"], meta["file"])
                        if best is None or score > best[0]:
                            best = cand
            if best:
                _, rec_off, pos, val, start, end, cid, fn = best
                assign_rows.append({
                    "rec_off": rec_off,
                    "field_pos": pos,
                    "target_off": val,
                    "stream_start": start,
                    "stream_end": end,
                    "cluster_id": cid,
                    "stream_file": fn,
                    "delta_from_start": val - start,
                })

        assign_csv = os.path.join(args.outdir, "record_assignments.csv")
        with open(assign_csv, "w", newline="") as fcsv:
            w = csv.DictWriter(fcsv, fieldnames=list(assign_rows[0].keys()) if assign_rows else ["rec_off"])
            w.writeheader()
            for row in assign_rows:
                w.writerow(row)

if __name__ == "__main__":
    main()
