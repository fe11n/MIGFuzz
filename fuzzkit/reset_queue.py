import json
from pathlib import Path

RESET_THRESHOLD_SECONDS = 60 * 60 * 24 # 1 day
json_path = Path("fuzzkit/service_fuzz.json")

to_keep = {
    "com.apple.notifyd",
    "com.apple.sandboxd",
    "com.apple.screensharing",
    "com.apple.sysdiagnose",
    "com.apple.universalaccessd",
    "com.apple.syslogd",
    "com.apple.suhelperd",
    "com.apple.security.syspolicy",
    
}


def parse_duration_seconds(duration_str):
    """Converts a duration string like '1:23:45' or '1 day, 2:03:04' to seconds."""
    if not duration_str:
        return 0

    duration_str = str(duration_str).strip()
    days = 0
    time_part = duration_str

    if "," in duration_str:
        day_part, time_part = duration_str.split(",", 1)
        day_part = day_part.strip()
        time_part = time_part.strip()
        if "day" in day_part:
            try:
                days = int(day_part.split()[0])
            except (ValueError, IndexError):
                days = 0

    time_fields = time_part.split(":")
    if len(time_fields) == 3:
        hours_str, minutes_str, seconds_str = time_fields
    elif len(time_fields) == 2:
        hours_str = "0"
        minutes_str, seconds_str = time_fields
    else:
        try:
            return days * 86400 + int(float(time_part))
        except ValueError:
            return days * 86400

    try:
        hours = int(hours_str)
        minutes = int(minutes_str)
        seconds = int(float(seconds_str))
    except ValueError:
        return days * 86400

    return days * 86400 + hours * 3600 + minutes * 60 + seconds


with open(json_path, 'r') as f:
    data = json.load(f)

fuzzed = data.get("fuzzed", {})
fuzzing = data.get("fuzzing", [])
to_fuzz = data.get("to_fuzz", [])

services_to_move = []
for service_name, info in list(fuzzed.items()):
    if service_name in to_keep:
        continue
    duration_seconds = parse_duration_seconds(info.get("duration"))
    if duration_seconds < RESET_THRESHOLD_SECONDS:
        services_to_move.append(service_name)

for service_name in services_to_move:
    del fuzzed[service_name]
    if service_name not in to_fuzz:
        to_fuzz.append(service_name)

fuzzing_to_move = []
for service_name in list(fuzzing):
    if service_name in to_keep:
        continue
    # No duration info while running; treat as needing reset.
    fuzzing_to_move.append(service_name)

for service_name in fuzzing_to_move:
    fuzzing.remove(service_name)
    if service_name not in to_fuzz:
        to_fuzz.append(service_name)

data["fuzzed"] = fuzzed
data["fuzzing"] = fuzzing
data["to_fuzz"] = to_fuzz

with open(json_path, 'w') as f:
    json.dump(data, f, indent=2)

total_moved = len(services_to_move) + len(fuzzing_to_move)
print(
    "Moved {} services back to to_fuzz (fuzzed<1h: {}, fuzzing reset: {}).".format(
        total_moved,
        len(services_to_move),
        len(fuzzing_to_move),
    )
)
