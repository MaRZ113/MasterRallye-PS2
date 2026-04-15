from pathlib import Path
import struct, csv, collections, math

pak = Path("TNG.PAK").read_bytes()

patterns = {b"\x00\x00l\x00": "l", b"\x00\x00n\x00": "n", b"\x00\x00o\x00": "o"}
markers = []
for pat, name in patterns.items():
    i = 0
    while True:
        j = pak.find(pat, i)
        if j == -1:
            break
        markers.append((j, name))
        i = j + 1
markers.sort()

print("PAK size:", len(pak))
print("Marker count:", len(markers))
print("Root/main offset candidate @0x0C:", hex(struct.unpack_from("<I", pak, 0x0C)[0]))
print("Magic candidate @0x10:", hex(struct.unpack_from("<I", pak, 0x10)[0]))
