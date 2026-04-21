import os
import json
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt

base_path = Path("/Users/fuzz_vr/Workspace/MachServerFuzz/experiment/exp1/results/2026-01-28")

services = [d for d in base_path.iterdir() if d.is_dir()]

num_services = len(services)

fig, axes = plt.subplots(nrows=num_services, ncols=1, figsize=(10, num_services * 2), sharex=True)

for i, service in enumerate(services):
    history_file = service / "coverage_history.jsonl"
    if history_file.exists():
        timestamps = []
        offsets = []
        with open(history_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                timestamps.append(datetime.fromisoformat(data['timestamp']))
                offsets.append(data['offsets'])
        if timestamps:
            start_time = timestamps[0]
            timestamps_rel = [(t - start_time).total_seconds() / 60 for t in timestamps]  # minutes
            axes[i].plot(timestamps_rel, offsets)
            axes[i].set_title(service.name)
            axes[i].set_ylabel('Offsets')

axes[-1].set_xlabel('Time (minutes from start)')

plt.tight_layout()
plt.savefig('coverage_plot.png')