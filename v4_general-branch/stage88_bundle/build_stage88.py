import pandas as pd
from pathlib import Path

BASE = Path(__file__).resolve().parent
stage87 = pd.read_csv(BASE.parent / 'stage87_bundle' / 'manifests' / 'stage87_quickrace_field_decoder.csv')

# Rebuild derived manifests for Stage 88 from Stage 87 field offsets.
# This script intentionally stays deterministic and data-driven.

def hx(s: str) -> int:
    return int(str(s), 16)

stage87['offset'] = stage87['offset_hex'].map(hx)
stage87['file_short'] = stage87['file'].str.replace('.bin', '', regex=False)

# Example: write a simplified nav decoder table
rows = []
for file, g in stage87.groupby('file_short'):
    g = g.sort_values('offset')
    nav = g[g['field_group'] == 'nav'].sort_values('offset')
    if len(nav):
        rows.append({
            'file': file,
            'decoder_class': g['decoder_class'].iloc[0],
            'nav_fields_present': ' | '.join(nav['field_name'].tolist()),
            'nav_field_offsets': ' | '.join(nav['offset_hex'].tolist()),
        })

out = pd.DataFrame(rows)
out.to_csv(BASE / 'manifests' / 'stage88_nav_link_decoder.csv', index=False)
print('Stage 88 minimal rebuild complete.')