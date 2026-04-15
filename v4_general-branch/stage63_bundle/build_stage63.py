from pathlib import Path
import mmap, struct

PAK_PATH = Path('/mnt/data/TNG.PAK')
TNG_PATH = Path('/mnt/data/TNG.000')

TARGETS = [
    b'FMV\CHALL04.PSS',
    b'\FMV\TROPHY.PSS',
    b'FMV\BFGOOD1.PSS',
]

with open(PAK_PATH, 'rb') as f:
    pak = f.read()

with open(TNG_PATH, 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    for name in TARGETS:
        off = pak.find(name)
        pre_u32_m24 = struct.unpack_from('<I', pak, off - 24)[0]
        # Stage 63 result: pre_u32_m24 is the exact pack start for page1_low16_bankroot late-FMV members
        print(name.decode('ascii', errors='ignore'), hex(off), hex(pre_u32_m24))
