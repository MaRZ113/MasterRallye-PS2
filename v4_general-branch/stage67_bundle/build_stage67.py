from pathlib import Path
import re
import pandas as pd

pak = Path("/mnt/data/TNG.PAK").read_bytes().decode("latin1", errors="ignore")
matches = [(m.start(), m.group()) for m in re.finditer(r'\\?FMV\\[A-Z0-9_]+\.PSS', pak, re.IGNORECASE)]
catalog = pd.DataFrame([{"pak_string_offset_hex": hex(off), "path": name} for off, name in matches])

# This Stage 67 helper is intentionally lightweight:
# it rebuilds the named FMV path catalog from TNG.PAK so later stages
# can join it with decoder registries derived from prior stage manifests.
out_dir = Path("/mnt/data/stage67_bundle/manifests")
out_dir.mkdir(parents=True, exist_ok=True)
catalog.to_csv(out_dir / "stage67_pak_fmv_path_catalog.csv", index=False)
print(f"cataloged {len(catalog)} FMV paths")
