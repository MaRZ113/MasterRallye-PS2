#!/usr/bin/env python3
from pathlib import Path
import pandas as pd, mmap, struct, hashlib, csv

TNG_PATH = Path('/mnt/data/TNG.000')
OUT = Path('/mnt/data/stage49_bundle')
MANI = OUT / 'manifests'
for d in [OUT, MANI]:
    d.mkdir(parents=True, exist_ok=True)

field_rules = pd.read_csv('/mnt/data/stage48_bundle/manifests/stage48_field_aware_router_43fc86.csv')
seed_v2 = pd.read_csv('/mnt/data/stage48_bundle/manifests/stage48_seed_router_table_v2.csv')

def std_status(promoted_status=None, routing_layer=None):
    mapping = {
        'promoted_clean': 'clean',
        'promoted_clean_soft': 'soft_clean',
        'secondary_evidence': 'evidence',
        'rejected': 'rejected',
        'primary_clean': 'clean',
        'reject_nonstandard': 'rejected',
    }
    return mapping.get(promoted_status, mapping.get(routing_layer, 'unresolved'))

pair_only = seed_v2[~((seed_v2['sig8']=='0000010c43fc9ae9') & (seed_v2['body_prefix']=='7321'))].copy()
pair_only = pair_only.drop_duplicates(['sig8','body_prefix','family_id','content_class','routing_layer','confidence','media_ids'])
marker = b'\x00\x00\x01\x0c'
watch = set(zip(pair_only['sig8'], pair_only['body_prefix']))
watch |= set(zip(field_rules['sig8'], field_rules['body_prefix']))
watch |= {('0000010c43fc9ae9','7321'), ('0000010c43fc86e9','7243')}

target_offsets = sorted({8,0x14,0x1c,0x20,0x24,0x28,0x88,0x94,0xa4,0x148,0x164})
rows = []
with open(TNG_PATH,'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    pos = 0
    while True:
        idx = mm.find(marker, pos)
        if idx == -1:
            break
        sig8 = mm[idx:idx+8].hex()
        bp = mm[idx+8:idx+10].hex()
        if (sig8, bp) in watch:
            rec = {'record_offset': idx, 'sig8': sig8, 'body_prefix': bp}
            for off in target_offsets:
                rec[f'pos{off:03x}'] = struct.unpack_from('<I', mm, idx+off)[0]
            rows.append(rec)
        pos = idx + 1
    mm.close()

live_df = pd.DataFrame(rows).sort_values(['sig8','body_prefix','record_offset'])
live_df.to_csv(MANI/'stage49_live_watched_hits.csv', index=False)
