from pathlib import Path
import pandas as pd

# Stage 99 bundle regeneration helper.
# This scaffold documents the artifact set produced during the AI_3_3 variant transfer pass.
base = Path('/mnt/data/stage99_bundle')
print('Stage 99 bundle files:')
for p in sorted(base.rglob('*')):
    if p.is_file():
        print(p.relative_to(base))
