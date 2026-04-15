#!/usr/bin/env python3
"""
Stage 81 build helper.
Replays the UiSelect / List value payload decoder pass by:
1. loading extracted RaceResults and Language member blobs
2. collecting printable anchors
3. inferring member name / type / inline literal / path tokens
4. exporting CSV manifests for field and readiness analysis
"""
