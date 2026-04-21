#!/usr/bin/env python3
"""
单次 litecov 统计脚本。
- 从服务目录的 run.sh 解析 instrument_module / DYLD / harness
- 遍历 out/ 下所有样本
- 对每个样本运行 litecov + harness
- 直接打印 coverage 行
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

SERVICE_DIR = Path("/Users/fuzz_vr/Workspace/MachServerFuzz/experiment/exp1/results/2026-01-26/com.apple.coreservices.useractivityd")
LITECOV_PATH = Path(
    "/Users/fuzz_vr/Workspace/MachServerFuzz/jackalope-modifications/build/Jackalope/TinyInst/Release/litecov"
)

COV_LINE_RE = re.compile(r"^.+\+[0-9a-fA-F]+$")


def _parse_run_sh(service_dir: Path) -> tuple[str, str, str]:
    run_sh = service_dir / "run.sh"
    if not run_sh.exists():
        raise FileNotFoundError(f"run.sh not found: {run_sh}")

    cmd_line = ""
    with run_sh.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "coreaudiofuzzer" in line:
                cmd_line = line.strip()
                break

    if not cmd_line:
        raise ValueError("No fuzz command found in run.sh")

    # remove leading sudo/script wrapper and trailing redirection
    if "sudo -E script -q /dev/null" in cmd_line:
        cmd_line = cmd_line.split("sudo -E script -q /dev/null", 1)[1].strip()
    if ">>" in cmd_line:
        cmd_line = cmd_line.split(">>", 1)[0].strip()

    tokens = shlex.split(cmd_line)

    instrument_module = ""
    dyld = ""
    harness = ""

    for i, tok in enumerate(tokens):
        if tok == "-instrument_module" and i + 1 < len(tokens):
            instrument_module = tokens[i + 1]
        if tok == "-target_env" and i + 1 < len(tokens):
            val = tokens[i + 1]
            if val.startswith("DYLD_INSERT_LIBRARIES="):
                dyld = val.split("=", 1)[1]

    if "--" in tokens:
        idx = tokens.index("--")
        if idx + 1 < len(tokens):
            harness = tokens[idx + 1]

    if not instrument_module:
        raise ValueError("instrument_module not found in run.sh")
    if not dyld:
        raise ValueError("DYLD_INSERT_LIBRARIES not found in run.sh")
    if not harness:
        raise ValueError("harness not found in run.sh")

    return instrument_module, harness, dyld


def main() -> int:
    if not SERVICE_DIR.exists():
        print(f"SERVICE_DIR not found: {SERVICE_DIR}")
        return 1
    if not LITECOV_PATH.exists():
        print(f"LITECOV_PATH not found: {LITECOV_PATH}")
        return 1

    try:
        instrument_module, harness_raw, dyld_raw = _parse_run_sh(SERVICE_DIR)
    except Exception as e:
        print(f"Parse run.sh failed: {e}")
        return 1

    out_dir = SERVICE_DIR / "out"
    if not out_dir.exists():
        print(f"OUT_DIR not found: {out_dir}")
        return 1
    harness_path = (SERVICE_DIR / harness_raw).resolve()
    dyld_path = (SERVICE_DIR / dyld_raw).resolve()
    if not harness_path.exists():
        print(f"HARNESS_PATH not found: {harness_path}")
        return 1

    print("Parsed from run.sh:")
    print(f"  instrument_module = {instrument_module}")
    print(f"  DYLD_INSERT_LIBRARIES = {dyld_raw}")
    print(f"  harness = {harness_raw}")
    print("Resolved paths:")
    print(f"  DYLD_INSERT_LIBRARIES = {dyld_path}")
    print(f"  harness = {harness_path}")

    covered = set()

    for sample in sorted(out_dir.iterdir()):
        if not sample.is_file():
            continue

        cmd = [
            str(LITECOV_PATH),
            "-instrument_module",
            instrument_module,
            "-coverage_file",
            "/dev/stdout",
            "-target_env",
            f"DYLD_INSERT_LIBRARIES={dyld_path}",
            "--",
            str(harness_path),
            "-f",
            str(sample),
        ]

        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            cwd=str(SERVICE_DIR),
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and COV_LINE_RE.match(line):
                covered.add(line)

    for line in sorted(covered):
        print(line)
    print(f"Unique coverage lines: {len(covered)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
