from pathlib import Path
import csv

pak = Path('/mnt/data/TNG.PAK').read_bytes()
out_dir = Path('/mnt/data/stage62_bundle/manifests')
out_dir.mkdir(parents=True, exist_ok=True)

members = [
    ('FMV\CHALL04.PSS', 0x15fcb, 0x15ef8, 0x127c, 0x0900),
    ('\FMV\TROPHY.PSS', 0x1b34f, 0x15fb6, 0x0c4c, 0x0600),
    ('FMV\BFGOOD1.PSS', 0x1d362, 0x15d29, 0x337c, 0x0900),
]

def find_all(bs):
    res=[]; start=0
    while True:
        i=pak.find(bs,start)
        if i==-1: break
        res.append(i); start=i+1
    return res

rows=[]
for path,string_offset,page_lift,sel_a,sel_b in members:
    packed = (sel_b << 16) | sel_a
    rows.append({
        'path': path,
        'page_lift_target_hex': hex(page_lift),
        'packed_member_key_hex': hex(packed),
        'page_lift_occurrence_count': len(find_all(page_lift.to_bytes(4, 'little'))),
        'packed_member_key_occurrence_count': len(find_all(packed.to_bytes(4, 'little'))),
        'page_lift_word_offset_hex': hex(string_offset - 8),
        'packed_member_word_offset_hex': hex(string_offset - 4),
    })

with (out_dir / 'stage62_page1_compound_member_keys.csv').open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print('stage62 artifacts rebuilt')
