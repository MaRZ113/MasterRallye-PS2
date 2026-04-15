import struct, mmap, os, json, subprocess, tempfile, pandas as pd

PAK_PATH = "/mnt/data/TNG.PAK"
TNG_PATH = "/mnt/data/TNG.000"

# Selected Stage 68 early-u16 payload-edge candidates.
SELECTED = {
    "INV1":     {"pak_off": 0xD0D4, "field_rel": -24, "transform": "direct", "const": 0x0},
    "MICROIDS": {"pak_off": 0x786C, "field_rel": -8,  "transform": "direct", "const": 0xA0000000},
    "CHALL02":  {"pak_off": 0x8F62, "field_rel": -32, "transform": "direct", "const": 0x0},
    "GO2":      {"pak_off": 0x6D35, "field_rel": -24, "transform": "direct", "const": 0x60000000},
    "FUJ3":     {"pak_off": 0x5422, "field_rel": -24, "transform": "swap16", "const": 0x10000000},
    "ELF3":     {"pak_off": 0xF311, "field_rel": -24, "transform": "direct", "const": 0x0},
}

def swap16(v: int) -> int:
    return ((v & 0xFFFF) << 16) | ((v >> 16) & 0xFFFF)

def u32le(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]

with open(PAK_PATH, "rb") as f:
    pak = f.read()
with open(TNG_PATH, "rb") as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

PACK = b"\x00\x00\x01\xba"

def nearest_pack(target: int, radius: int = 0x20000):
    lo = max(0, target - radius)
    hi = min(len(mm), target + radius)
    chunk = mm[lo:hi]
    best = None
    start = 0
    while True:
        idx = chunk.find(PACK, start)
        if idx < 0:
            break
        off = lo + idx
        delta = abs(off - target)
        if best is None or delta < best[1]:
            best = (off, delta)
        start = idx + 1
    return best

rows = []
for name, spec in SELECTED.items():
    raw = u32le(pak, spec["pak_off"] + spec["field_rel"])
    val = swap16(raw) if spec["transform"] == "swap16" else raw
    if val >= spec["const"]:
        target = val - spec["const"]
        np = nearest_pack(target)
        rows.append({
            "name": name,
            "raw_u32_hex": hex(raw),
            "target_hex": hex(target),
            "nearest_pack_hex": hex(np[0]) if np else "",
            "snap_delta_bytes": np[1] if np else None,
        })

df = pd.DataFrame(rows)
print(df)
