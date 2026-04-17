#!/usr/bin/env python3
from pathlib import Path
import csv, hashlib, subprocess

TNG_PATH = Path('/mnt/data/TNG.000')
OUT_DIR = Path('/mnt/data/stage47_rebuild')
CAND_DIR = OUT_DIR / 'candidate_media'
SHEET_DIR = OUT_DIR / 'contact_sheets'
MANI_DIR = OUT_DIR / 'manifests'
OUT_DIR.mkdir(parents=True, exist_ok=True)
CAND_DIR.mkdir(exist_ok=True)
SHEET_DIR.mkdir(exist_ok=True)
MANI_DIR.mkdir(exist_ok=True)

CANDIDATES = [
    ('rank01', 0x34FD2000, 0x351D2000),
    ('rank02', 0x3625B000, 0x3645B000),
    ('rank03', 0x36AA4000, 0x36CA4000),
    ('rank05', 0x30B67000, 0x30D67000),
    ('rank06', 0x350D5000, 0x352D5000),
]

with open(TNG_PATH, 'rb') as f:
    for rank, start, end in CANDIDATES:
        f.seek(start)
        data = f.read(end - start)
        out = CAND_DIR / f'43fc86_stage47_{rank}_{start:08X}_{end:08X}.pss'
        out.write_bytes(data)
        png = SHEET_DIR / (out.stem + '.png')
        subprocess.run(['ffmpeg','-y','-v','error','-i',str(out),'-vf','fps=1/2,scale=256:-1,tile=3x2','-frames:v','1',str(png)], check=False)

h = hashlib.sha256()
with open(TNG_PATH, 'rb') as fp:
    for chunk in iter(lambda: fp.read(1024 * 1024), b''):
        h.update(chunk)
with open(MANI_DIR / 'stage47_tng_integrity_check.csv', 'w', newline='') as fp:
    w = csv.writer(fp)
    w.writerow(['path','size_bytes','sha256'])
    w.writerow([str(TNG_PATH), TNG_PATH.stat().st_size, h.hexdigest().upper()])
