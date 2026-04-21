#!/bin/bash
# Auto-generated fuzzing script for com.apple.syslogd
# Generated on: $(date)

cd "$(dirname "$0")" || exit

echo "Starting fuzzing for com.apple.syslogd, logging to log.txt..."
sudo -E script -q /dev/null ../../jackalope-modifications/build/Release/coreaudiofuzzer -hook_functions true -in corpus -out out -delivery file -instrument_module syslogd -target_module harness -target_method _fuzz -nargs 1 -iterations 1000 -persist -loop -dump_coverage -cmp_coverage -target_env DYLD_INSERT_LIBRARIES=../../libmach-modify.dylib -nthreads 5 -- ./harness -f @@ >> log.txt 2>&1
