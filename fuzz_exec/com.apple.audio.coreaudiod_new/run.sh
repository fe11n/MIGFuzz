#!/bin/bash
# Auto-generated fuzzing script for com.apple.audio.coreaudiod
# Generated on: $(date)

cd "$(dirname "$0")" || exit

TIME=$(date +%Y%m%d_%H%M)
OUT_DIR="out_$TIME"

# Get the actual user who ran sudo
REAL_USER=${SUDO_USER:-$USER}

# Original command to run
original_command="sudo -E script -q /dev/null ../../jackalope-modifications/build/Release/coreaudiofuzzer -hook_functions true -in corpus -out \"$OUT_DIR\" -delivery file -instrument_module CoreAudio -target_module harness -target_method _fuzz -nargs 1 -iterations 1000 -persist -loop -dump_coverage -cmp_coverage -generate_unwind -target_env DYLD_INSERT_LIBRARIES=../../libmach-modify.dylib -nthreads 5 -- ./harness -f @@"

# Initialize command with the original command
command="$original_command"

echo "Starting fuzzing for com.apple.audio.coreaudiod, logging to $OUT_DIR/log.txt..."

# Ensure output directory exists before redirection
mkdir -p "$OUT_DIR"
# Change ownership to the real user
chown -R "$REAL_USER" "$OUT_DIR"

# Loop to keep restarting the command if it stops
while true; do
  echo "Starting the fuzzing command..."
  eval $command >> "$OUT_DIR/log.txt" 2>&1

  # Check if the command exited with an error code
  if [ $? -ne 0 ]; then
    echo "Command stopped unexpectedly. Restarting..."
    
    # Only try to restore state if state file exists
    if [ -f \"$OUT_DIR/state.dat\" ]; then
      echo "State file found. Attempting to resume session..."
      command=$(echo "$original_command" | sed "s/-in [^ ]*/-in -/")
    else
      echo "No state file found. Restarting fresh..."
      command="$original_command"
    fi
    sleep 2
  else
    echo "Command completed successfully. Stopping loop."
    break
  fi
done
