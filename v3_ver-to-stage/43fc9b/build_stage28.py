# Rebuild script placeholder for Stage 28.
# This stage was generated from the full TNG.000 using a family-aware secondary scout on 43fc9b.
# Inputs:
#   /mnt/data/TNG_rebuilt/TNG.000
# Outputs:
#   candidate_media/
#   contact_sheets/
#   manifests/
# Main logic:
#   1) scan 0000010c43fc9b** hits
#   2) score common field positions for repeated u32 windows
#   3) export fixed-size 0x2A0000 candidate windows
#   4) ffprobe each candidate and emit family-hint metadata