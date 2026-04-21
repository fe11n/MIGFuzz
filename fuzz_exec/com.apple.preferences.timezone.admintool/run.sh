#!/bin/bash
# Auto-generated fuzzing script for com.apple.preferences.timezone.admintool
# Generated on: $(date)

cd "$(dirname "$0")" || exit

echo "Starting fuzzing for com.apple.preferences.timezone.admintool, logging to log.txt..."
sudo -E script -q /dev/null ../../jackalope-modifications/build/Release/coreaudiofuzzer -hook_functions true -in corpus -out out -delivery file -instrument_module TimeZoneAdminTool -target_module harness -target_method _fuzz -nargs 1 -iterations 1000 -persist -loop -dump_coverage -cmp_coverage -target_env DYLD_INSERT_LIBRARIES=../../libmach-modify.dylib -nthreads 5 -- ./harness -f @@ >> log.txt 2>&1
