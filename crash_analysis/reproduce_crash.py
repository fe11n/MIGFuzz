#!/usr/bin/env python3

import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple


def get_service_binary_name(service_name: str, mig_services_dir: Path) -> Optional[str]:
    """Infer the binary name for a service directory by ignoring common non-binary extensions."""
    service_dir = mig_services_dir / service_name
    if not service_dir.exists():
        return None

    ignore_exts = ['.json', '.h', '.c', '.py', '.sh', '.md', '.i64', '.txt']
    candidates = []
    for path in service_dir.iterdir():
        if path.is_file() and path.suffix not in ignore_exts and not path.name.startswith('.'):
            if path.suffix == '':
                candidates.append(path.name)

    if not candidates:
        return None

    if len(candidates) > 1:
        for candidate in candidates:
            if candidate in service_name:
                return candidate
        return candidates[0]

    return candidates[0]


def check_launchctl(service_name: str, target_uid: int) -> Tuple[bool, Optional[str]]:
    """Inspect launchctl state for crash hints."""
    cmd = ['launchctl', 'print', f'system/{service_name}']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        cmd = ['launchctl', 'print', f'user/{target_uid}/{service_name}']
        result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        output = result.stdout
        if "successive crash" in output:
            return True, "successive crash detected"

        for line in output.split('\n'):
            if "last exit code" in line:
                val = line.split('=')[1].strip()
                if "(never exited)" not in val and val != "0":
                    return True, f"non-zero exit code: {val}"

    return False, None


def check_diagnostic_reports(binary_name: str, start_time: datetime.datetime) -> Tuple[bool, Optional[str]]:
    """Check DiagnosticReports for new crash logs after start_time."""
    diag_dirs = [
        Path(os.path.expanduser('~/Library/Logs/DiagnosticReports')),
        Path('/Library/Logs/DiagnosticReports'),
    ]

    for diag_dir in diag_dirs:
        if not diag_dir.exists():
            continue

        for report in diag_dir.iterdir():
            if report.name.startswith(binary_name):
                mtime = datetime.datetime.fromtimestamp(report.stat().st_mtime)
                if mtime > start_time:
                    return True, report.name
    return False, None


def reproduce_crashes(
    fuzz_exec_dir: Path,
    mig_services_dir: Path,
    target_service: Optional[str],
    target_uid: int,
    reproduce_script: Path,
    poc_construct_dir: Path,
) -> Dict[str, Dict[str, Dict[str, str]]]:
    """Reproduce crashes for services and record results."""
    aggregated_results: Dict[str, Dict[str, Dict[str, str]]] = {}

    for service_dir in fuzz_exec_dir.iterdir():
        if not service_dir.is_dir():
            continue

        service_name = service_dir.name
        if target_service and service_name != target_service:
            continue

        icrashes_dir = service_dir / 'out' / 'icrashes'
        if not icrashes_dir.exists():
            continue

        result_json_path = service_dir / 'out' / 'crash_rep_result.json'
        rep_results: Dict[str, Dict[str, str]] = {}
        if result_json_path.exists():
            try:
                rep_results = json.loads(result_json_path.read_text())
            except Exception:
                pass

        binary_name = get_service_binary_name(service_name, mig_services_dir)
        if not binary_name:
            print(f"Warning: Could not determine binary name for {service_name}")
            binary_name = service_name
        else:
            print(f"Service Binary: {binary_name}")

        for crash_file in icrashes_dir.iterdir():
            if not crash_file.is_file() or crash_file.name.endswith('.log') or crash_file.name.startswith('.'):
                continue

            if not (icrashes_dir / f"{crash_file.name}.log").exists():
                continue

            if crash_file.name in rep_results:
                print(f"Skipping {service_name} / {crash_file.name} (already in crash_rep_result.json)")
                continue

            print(f"Reproducing {service_name} / {crash_file.name}...")

            start_time = datetime.datetime.now()
            cmd = [sys.executable, str(reproduce_script), str(crash_file)]
            proc = subprocess.run(cmd, check=False, cwd=poc_construct_dir)
            message_sent = (proc.returncode == 0)

            time.sleep(2)  # Small wait to let crash artifacts land on disk

            is_crashed = False
            crash_reason = ""

            lc_crashed, lc_reason = check_launchctl(service_name, target_uid)
            if lc_crashed:
                is_crashed = True
                crash_reason = f"launchctl ({lc_reason})"
                print(f"  -> Verified via {crash_reason}")

            if not is_crashed:
                dr_crashed, dr_report = check_diagnostic_reports(binary_name, start_time)
                if dr_crashed:
                    is_crashed = True
                    crash_reason = f"DiagnosticReports ({dr_report})"
                    print(f"  -> Verified via {crash_reason}")

            reproduce_method = "message" if is_crashed else None
            generator_sent = None

            # If message reproduction failed, try generator
            if not is_crashed:
                print(f"  -> Message replay failed (sent={message_sent}). Trying generator...")
                gen_script = poc_construct_dir / 'reproduce_crash_bygenerator.py'
                
                if gen_script.exists():
                    start_time_gen = datetime.datetime.now()
                    cmd_gen = [sys.executable, str(gen_script), str(crash_file)]
                    proc_gen = subprocess.run(cmd_gen, check=False, cwd=poc_construct_dir)
                    generator_sent = (proc_gen.returncode == 0)

                    time.sleep(2)

                    lc_crashed, lc_reason = check_launchctl(service_name, target_uid)
                    if lc_crashed:
                        is_crashed = True
                        crash_reason = f"launchctl ({lc_reason})"
                        print(f"  -> Verified via {crash_reason}")

                    if not is_crashed:
                        dr_crashed, dr_report = check_diagnostic_reports(binary_name, start_time_gen)
                        if dr_crashed:
                            is_crashed = True
                            crash_reason = f"DiagnosticReports ({dr_report})"
                            print(f"  -> Verified via {crash_reason}")
                    
                    if is_crashed:
                        reproduce_method = "generator"
                        start_time = start_time_gen
                else:
                    print(f"  -> Generator script not found at {gen_script}")

            rep_results[crash_file.name] = {
                "reproduced": is_crashed,
                "timestamp": str(start_time),
                "reason": crash_reason,
                "message_sent": message_sent,
                "generator_sent": generator_sent,
                "reproduction_method": reproduce_method,
                "conwith_generator": None
            }
            
            # Analyze consistency
            analyze_script = poc_construct_dir / 'analyze_crash_diff.py'
            if analyze_script.exists():
                cmd_analyze = [sys.executable, str(analyze_script), str(crash_file)]
                # Capture output to avoid printing to terminal and to parse result
                proc_analyze = subprocess.run(cmd_analyze, capture_output=True, text=True, cwd=poc_construct_dir)
                
                # Parse output for CONWITH_GENERATOR:xxx
                for line in proc_analyze.stdout.splitlines():
                    if line.startswith("CONWITH_GENERATOR:"):
                        val_str = line.split(":", 1)[1].strip().lower()
                        rep_results[crash_file.name]['conwith_generator'] = (val_str == 'true')
                        break

            if is_crashed:
                print("  -> Crash Reproduced!")
            else:
                print("  -> Crash NOT Reproduced.")

        result_json_path.write_text(json.dumps(rep_results, indent=4))
        aggregated_results[service_name] = rep_results

    return aggregated_results


if __name__ == "__main__":
    print("This module is intended to be imported and used by auto_crash_check.py")
