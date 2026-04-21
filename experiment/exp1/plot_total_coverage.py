import os
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

sns.set_style('ticks')

base_path = Path("/Users/fuzz_vr/Workspace/MachServerFuzz/experiment/exp1/results/2026-01-28")

services = [d for d in base_path.iterdir() if d.is_dir()]

service_data = {}
all_times = set()

for service in services:
    history_file = service / "coverage_history.jsonl"
    if history_file.exists():
        times = []
        offsets = []
        with open(history_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                ts = datetime.fromisoformat(data['timestamp'])
                times.append(ts)
                offsets.append(data['offsets'])
                all_times.add(ts)
        service_data[service.name] = (times, offsets)

sorted_times = sorted(all_times)
min_time = min(sorted_times)
sorted_times_rel = [(t - min_time).total_seconds() / 3600 for t in sorted_times]
total_offsets = []

for t in sorted_times:
    total = 0
    for name, (times, offsets) in service_data.items():
        # find the latest offset before or at t
        latest_offset = 0
        for i, ts in enumerate(times):
            if ts <= t:
                latest_offset = offsets[i]
            else:
                break
        total += latest_offset
    total_offsets.append(total)

import colorspacious as cs
import matplotlib.colors as mcolors

color_schemes = []
for i in range(16):
    h1 = i / 16.0
    h2 = (i / 16.0 + 0.5) % 1.0
    rgb1 = mcolors.hsv_to_rgb([h1, 0.5, 0.8])  # lower saturation for print
    rgb2 = mcolors.hsv_to_rgb([h2, 0.5, 0.8])
    # adjust L to 70 in CIELab
    lab1 = cs.cspace_convert(rgb1, "sRGB1", "CIELab")
    lab1[0] = 70
    rgb1_adj = np.clip(cs.cspace_convert(lab1, "CIELab", "sRGB1"), 0, 1)
    lab2 = cs.cspace_convert(rgb2, "sRGB1", "CIELab")
    lab2[0] = 70
    rgb2_adj = np.clip(cs.cspace_convert(lab2, "CIELab", "sRGB1"), 0, 1)
    color_schemes.append((rgb1_adj, rgb2_adj))

selected_scheme = color_schemes[8]  # 3rd row, 1st column (0-based: row 2, col 0)
line_color, dash_color = selected_scheme

plt.figure(figsize=(16, 10))
plt.plot(sorted_times_rel, total_offsets, color=line_color, linewidth=3)
plt.xlabel('Time (hours from start)', fontsize=14)
plt.ylabel('Cumulative Total Offsets', fontsize=14)
plt.title('Cumulative Total Coverage Offsets Over Time', fontsize=16)

# Add markers for service start times
service_starts = [min(times) for times, _ in service_data.values() if times]
for start in service_starts:
    if start > min_time:
        rel_h = (start - min_time).total_seconds() / 3600
        y_at_start = np.interp(rel_h, sorted_times_rel, total_offsets)
        plt.plot([rel_h, rel_h], [0, y_at_start], color='gray', linestyle='--', alpha=0.5, linewidth=0.5)

plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('total_coverage_selected.png', dpi=300)