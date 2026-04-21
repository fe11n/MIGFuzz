#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVICES_ROOT = PROJECT_ROOT / "fuzz_exec"
ROOT_CORPUS_DIR = PROJECT_ROOT / "corpus"
JACKALOPE_BIN_REL = "../../jackalope-modifications/build/Release/coreaudiofuzzer"
DYLIB_REL_FROM_SERVICE = "../../libmach-modify.dylib"


def _run(cmd: List[str], cwd: Optional[Path] = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def _run_build(cmd: List[str], cwd: Optional[Path] = None) -> None:
    # Build steps may need elevated privileges if previous artifacts are root-owned.
    # This will prompt for a password in the terminal when required.
    subprocess.run(["sudo", "-E"] + cmd, cwd=str(cwd) if cwd else None, check=True)


def _sudo_copy(src: Path, dst: Path) -> None:
    subprocess.run(["sudo", "-E", "cp", "-f", str(src), str(dst)], check=True)


def _sudo_chmod(path: Path, mode: str) -> None:
    subprocess.run(["sudo", "-E", "chmod", mode, str(path)], check=True)


def build_dylib() -> None:
    cmd = [
        "clang",
        "-dynamiclib",
        "-w",
        "-o",
        "libmach-modify.dylib",
        "mach-modify.c",
        "-ldl",
        "-I./fuzz_helpers",
        "-framework",
        "CoreFoundation",
    ]
    _run_build(cmd, cwd=PROJECT_ROOT)


def _load_service_config(service_dir: Path) -> Dict:
    service_json = service_dir / "service.json"
    with open(service_json, "r") as f:
        return json.load(f)


def build_harness(service_name: str, service_dir: Path) -> None:
    generate_msg_cc = service_dir / "generate_message.cc"
    if not generate_msg_cc.exists():
        raise FileNotFoundError(f"Missing {generate_msg_cc}")

    harness_output = service_dir / "harness"

    sources = [
        "harness.mm",
        "fuzz_helpers/debug.cc",
        "fuzz_helpers/initialization.cc",
        "fuzz_helpers/load_library.cc",
        "fuzz_helpers/services_manager.cc",
        str(generate_msg_cc),
        "fuzz_helpers/tool_lib.cc",
    ]

    cmd = [
        "clang++",
        "-fno-omit-frame-pointer",
        "-w",
        "-std=c++17",
        "-I./fuzz_helpers",
        "-I.",
        f"-I./fuzz_exec/{service_name}",
        "-framework",
        "Foundation",
        "libmach-modify.dylib",
    ] + sources + ["-o", str(harness_output)]

    _run_build(cmd, cwd=PROJECT_ROOT)

    dylib_src = PROJECT_ROOT / "libmach-modify.dylib"
    dylib_dst = service_dir / "libmach-modify.dylib"
    if dylib_src.exists():
        # Service directories may contain root-owned artifacts from previous runs.
        _sudo_copy(dylib_src, dylib_dst)


def prepare_dirs_and_corpus(service_dir: Path) -> Tuple[Path, Path]:
    corpus_dir = service_dir / "corpus"
    out_dir = service_dir / "out"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy initial corpus from project root if destination is empty
    if ROOT_CORPUS_DIR.exists() and not any(corpus_dir.iterdir()):
        for item in ROOT_CORPUS_DIR.iterdir():
            if item.is_file() and not item.name.startswith("."):
                shutil.copy2(item, corpus_dir)

    return corpus_dir, out_dir


def write_run_sh(service_name: str, service_dir: Path, config: Dict, resume: bool = False) -> None:
    fuzz_cfg = config.get("fuzz", {})

    # Build a command identical in spirit to existing build+fuzz script generation.
    corpus_input = "-" if resume else "corpus"

    cmd_parts = [
        "sudo",
        "-E",
        "script",
        "-q",
        "/dev/null",
        JACKALOPE_BIN_REL,
        "-hook_functions",
        "true",
        "-in",
        corpus_input,
        "-out",
        '\\"$OUT_DIR\\"',
        "-delivery",
        "file",
        "-instrument_module",
        str(fuzz_cfg.get("instrument_module", service_name)),
        "-target_module",
        "harness",
        "-target_method",
        "_fuzz",
        "-nargs",
        "1",
        "-iterations",
        str(fuzz_cfg.get("iterations", 1000)),
        "-persist",
        "-loop",
        "-dump_coverage",
        "-cmp_coverage",
        "-generate_unwind",
        "-target_env",
        f"DYLD_INSERT_LIBRARIES={DYLIB_REL_FROM_SERVICE}",
        "-nthreads",
        str(fuzz_cfg.get("threads", 5)),
        "--",
        "./harness",
        "-f",
        "@@",
    ]

    original_command = " ".join(cmd_parts)

    run_sh_path = service_dir / "run.sh"
    script_content = f"""#!/bin/bash
# Auto-generated fuzzing script for {service_name}
# Generated on: $(date)

cd "$(dirname "$0")" || exit

TIME=$(date +%Y%m%d_%H%M)
OUT_DIR="out_$TIME"

# Get the actual user who ran sudo
REAL_USER=${{SUDO_USER:-$USER}}

# Original command to run
original_command="{original_command}"

# Initialize command with the original command
command="$original_command"

echo "Starting fuzzing for {service_name}, logging to $OUT_DIR/log.txt..."

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
    if [ -f "$OUT_DIR/state.dat" ]; then
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
"""

    # Service directories may be root-owned; install run.sh via sudo.
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write(script_content)
        tmp_path = Path(tmp.name)
    try:
        _sudo_copy(tmp_path, run_sh_path)
        _sudo_chmod(run_sh_path, "755")
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    # Match original UX: show how to run the generated script.
    rel_run_sh = run_sh_path.relative_to(PROJECT_ROOT)
    print("To run:")
    print(f"sudo {rel_run_sh}")


def discover_services() -> Dict[str, Path]:
    services: Dict[str, Path] = {}
    if not SERVICES_ROOT.exists():
        return services

    for p in SERVICES_ROOT.iterdir():
        if not p.is_dir():
            continue
        if not (p / "service.json").exists():
            continue
        services[p.name] = p

    return services


def prepare_one(service_name: str, service_dir: Path, resume: bool = False) -> None:
    config = _load_service_config(service_dir)
    prepare_dirs_and_corpus(service_dir)
    build_harness(service_name, service_dir)
    write_run_sh(service_name, service_dir, config, resume=resume)


def main() -> int:
    if sys.platform != "darwin":
        print("Error: this tool is intended to run on macOS.")
        return 2

    parser = argparse.ArgumentParser(
        description="Prepare MachServerFuzz services for fuzzing (build dylib+harness, copy corpus, generate run.sh)."
    )
    parser.add_argument(
        "service",
        nargs="?",
        help="Service directory name under fuzz_exec (e.g. com.apple.bsd.dirhelper). If omitted, prepare all services.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Generate run.sh with resume input (uses '-' as input corpus).",
    )
    args = parser.parse_args()

    services = discover_services()
    if not services:
        print(f"No services found under {SERVICES_ROOT}")
        return 1

    # Always build dylib once at project root (same behavior as existing build flow).
    try:
        build_dylib()
    except subprocess.CalledProcessError as e:
        print(f"Failed to build libmach-modify.dylib: {e}")
        return e.returncode or 1

    targets: List[Tuple[str, Path]]
    if args.service:
        if args.service not in services:
            print(f"Unknown service '{args.service}'. Available: {', '.join(sorted(services.keys()))}")
            return 1
        targets = [(args.service, services[args.service])]
    else:
        targets = [(name, path) for name, path in sorted(services.items(), key=lambda x: x[0].lower())]

    failed: List[str] = []
    for name, path in targets:
        try:
            print(f"\n=== Preparing {name} ===")
            prepare_one(name, path, resume=args.resume)
            print(f"✓ Prepared {name}")
        except Exception as e:
            print(f"✗ Failed preparing {name}: {e}")
            failed.append(name)

    if failed:
        print(f"\nDone with failures: {', '.join(failed)}")
        return 1

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
