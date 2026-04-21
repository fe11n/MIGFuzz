import os
import subprocess
import time
import signal
import sys
import argparse
import re
import json
from pathlib import Path
from datetime import datetime, timedelta

# 加入llm_utils模块所在的路径到sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from llm_utils.utils import log_message

# Configuration
# Assuming this script is in fuzzkit/batch_runner.py, so workspace root is parent directory
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
FUZZ_EXEC_DIR = WORKSPACE_ROOT / "fuzz_exec"
SERVICE_FUZZ_JSON = WORKSPACE_ROOT / "fuzzkit" / "service_fuzz.json"
AUTO_CRASH_CHECK = WORKSPACE_ROOT / "crash_analysis" / "auto_crash_check.py"
SUCCESS_RESULT_JSON = WORKSPACE_ROOT / "llm_message_checker" / "all_check_result.json"

def parse_duration(duration_str):
    """
    Parses a duration string (e.g., '24h', '30m', '3600s', '1d') into seconds.
    Default unit is seconds if no suffix is provided.
    """
    duration_str = str(duration_str).strip().lower()
    match = re.match(r'^(\d+)([smhd]?)$', duration_str)
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}. Use format like '24h', '30m', or '3600'.")
    
    value, unit = match.groups()
    value = int(value)
    
    if unit == 's' or unit == '':
        return value
    elif unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    elif unit == 'd':
        return value * 86400
    else:
        raise ValueError(f"Unknown time unit: {unit}")

def get_services(filter_names=None):
    """
    Scans fuzz_exec for services. 
    If filter_names is provided, only returns matching services.
    """
    services = []
    if not FUZZ_EXEC_DIR.exists():
        print(f"Error: {FUZZ_EXEC_DIR} does not exist.")
        return []

    for item in FUZZ_EXEC_DIR.iterdir():
        if item.is_dir() and (item / "run.sh").exists():
            if filter_names:
                if item.name in filter_names:
                    services.append(item)
            else:
                services.append(item)
    return sorted(services)

def load_service_queue():
    """Loads the list of services to fuzz from service_fuzz.json"""
    if not SERVICE_FUZZ_JSON.exists():
        print(f"Error: {SERVICE_FUZZ_JSON} does not exist.")
        return []

    try:
        with open(SERVICE_FUZZ_JSON, 'r') as f:
            data = json.load(f)
            return data.get("to_fuzz", [])
    except Exception as e:
        print(f"Error reading service_fuzz.json: {e}")
        return []


def load_success_hours():
    """Returns a mapping of service_name -> hours to fuzz based on success id count."""
    if not SUCCESS_RESULT_JSON.exists():
        return {}

    try:
        with open(SUCCESS_RESULT_JSON, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {SUCCESS_RESULT_JSON}: {e}")
        return {}

    services = data.get("services", {})
    result = {}
    for name, info in services.items():
        # Prefer reg_success_ids if present; otherwise fall back to org_success_ids.
        if isinstance(info, dict) and "reg_success_ids" in info:
            count = info.get("reg_success_ids", 0)
        else:
            count = info.get("org_success_ids", 0) if isinstance(info, dict) else 0

        try:
            count_int = int(count)
        except (TypeError, ValueError):
            count_int = 0

        # Clamp between 0 and 24 hours as requested.
        hours = max(0, min(count_int, 24))
        if hours == 0:
            continue  # skip zero-hour entries; will fall back to default
        result[name] = hours

    return result

def get_crash_count(service_dir):
    """Counts the number of unique crashes in the service's output directory."""
    # Assuming crashes are stored in 'out/crashes'
    # Adjust paths based on actual fuzzer output structure
    crash_dirs = ["out/crashes"]
    count = 0
    for d in crash_dirs:
        path = service_dir / d
        if path.exists() and path.is_dir():
            # Count files, excluding hidden ones
            count += len([f for f in path.iterdir() if f.is_file() and not f.name.startswith('.')])
    return count

def get_reproduced_count(service_dir):
    """Returns number of crashes marked reproduced in crash_rep_result.json"""
    result_json_path = service_dir / "out" / "crash_rep_result.json"
    if not result_json_path.exists():
        return 0
    try:
        with open(result_json_path, 'r') as f:
            data = json.load(f)
        return sum(1 for v in data.values() if isinstance(v, dict) and v.get("reproduced"))
    except Exception:
        return 0

def get_end_reason(service_dir):
    """
    Checks the last 10 lines of log.txt in the service directory.
    If '[-] PROGRAM ABORT : ' is found, returns that line and everything after it.
    Otherwise returns None.
    """
    log_path = service_dir / "log.txt"
    if not log_path.exists():
        return None

    try:
        # Read the file. ideally we'd use seek for large files but services likely stopped if we are checking this
        # or we can just read the last chunk.
        # Check last 4KB should be enough for last 10 lines
        file_size = log_path.stat().st_size
        with open(log_path, 'r', errors='ignore') as f:
            if file_size > 4096:
                f.seek(file_size - 4096)
            lines = f.readlines()
            
        # Get last 10 lines
        tail_lines = lines[-10:] if len(lines) > 10 else lines
        
        abort_idx = -1
        for i, line in enumerate(tail_lines):
            if line.strip().startswith("[-] PROGRAM ABORT : "):
                abort_idx = i
                break
        
        if abort_idx != -1:
            return "".join(tail_lines[abort_idx:]).strip()
            
    except Exception as e:
        print(f"Error reading log for end reason: {e}")
    
    return None

def update_service_status(service_name, status_type, info=None):
    """
    Updates the status in service_fuzz.json.
    status_type: 'start', 'stop'
    """
    if info is None:
        info = {}

    if not SERVICE_FUZZ_JSON.exists():
        return

    try:
        with open(SERVICE_FUZZ_JSON, 'r') as f:
            data = json.load(f)
        
        # Ensure structure exists
        if "to_fuzz" not in data: data["to_fuzz"] = []
        if "fuzzing" not in data: data["fuzzing"] = []
        if "fuzzed" not in data: data["fuzzed"] = {}

        if status_type == 'start':
            # Move from to_fuzz to fuzzing
            if service_name in data["to_fuzz"]:
                data["to_fuzz"].remove(service_name)
            if service_name not in data["fuzzing"]:
                data["fuzzing"].append(service_name)
                
        elif status_type == 'stop':
            # Move from fuzzing to fuzzed
            if service_name in data["fuzzing"]:
                data["fuzzing"].remove(service_name)
            
            start_time_ts = info.get("start_time")
            start_time_str = datetime.fromtimestamp(start_time_ts).isoformat() if start_time_ts else "unknown"

            # Check for end reason in log file
            # Need service directory to find log.txt
            # We don't have service_dir passed here directly, but we can reconstruct it or pass it.
            # info dict seems to lack service_dir, let's fix call sites or assume path
            service_dir = FUZZ_EXEC_DIR / service_name
            end_reason = get_end_reason(service_dir)

            entry = {
                "duration": format_time(info.get("duration", 0)),
                "status": info.get("status", "unknown"),
                "crash_num": info.get("crash_num", 0),
                "reproduced_num": info.get("reproduced_num", 0),
                "start_time": start_time_str,
                "end_time": datetime.now().isoformat()
            }
            if end_reason:
                entry["end_reason"] = end_reason
                
            data["fuzzed"][service_name] = entry
        
        with open(SERVICE_FUZZ_JSON, 'w') as f:
            json.dump(data, f, indent=2)
            
    except Exception as e:
        print(f"Error updating service_fuzz.json: {e}")

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))

def run_batch(services, default_duration_seconds, max_concurrent=10, durations_by_service=None):
    # Queue of services to run
    service_queue = services[:]
    # Currently running processes: {pid: {"name": name, "process": p, "start_time": t, "dir": dir}}
    running_processes = {}

    durations_by_service = durations_by_service or {}
    
    # Map service names to their directory paths
    service_dirs = {s.name: s for s in get_services()}
    
    # Use log_message from utils which handles both file and console output
    def log_event(msg):
        log_message(msg)
            
    log_event(f"Starting fuzzing manager. Total services: {len(services)}")
    log_event(f"Default Duration: {format_time(default_duration_seconds)}, Max Concurrent: {max_concurrent}")

    last_process_log_time = time.time()

    try:
        while service_queue or running_processes:
            current_time = time.time()

            # Hourly log of total system processes
            if current_time - last_process_log_time > 3600:
                try:
                    # Run 'ps -e' and count lines to get total processes
                    result = subprocess.run("ps -e | wc -l", shell=True, capture_output=True, text=True)
                    total_procs = result.stdout.strip()
                    log_event(f"System Monitor: Total processes running: {total_procs}")
                except Exception as e:
                    log_event(f"System Monitor Failed: {e}")
                last_process_log_time = current_time
            
            # 1. Check running processes
            finished_pids = []
            finished_pids = []
            for pid, p_info in running_processes.items():
                p = p_info["process"]
                name = p_info["name"]
                start_t = p_info["start_time"]
                target_duration = p_info["target_duration"]
                elapsed = current_time - start_t
                
                # Check if process finished naturally (crashed or stopped)
                if p.poll() is not None:
                    log_event(f"Service {name} stopped early after {format_time(elapsed)}")
                    crash_count = get_crash_count(p_info["dir"])
                    reproduced_count = 0
                    if crash_count > 0:
                        log_event(f"Running auto_crash_check -r for {name} (crashes: {crash_count})")
                        subprocess.run([sys.executable, str(AUTO_CRASH_CHECK), "-r", name], cwd=str(WORKSPACE_ROOT), check=False)
                        reproduced_count = get_reproduced_count(p_info["dir"])
                        log_event(f"Reproduced crashes for {name}: {reproduced_count}")
                    update_service_status(
                        name,
                        'stop',
                        {
                            "duration": elapsed,
                            "status": "stopped_early",
                            "crash_num": crash_count,
                            "reproduced_num": reproduced_count,
                            "start_time": start_t,
                        },
                    )
                    finished_pids.append(pid)
                    continue
                
                # Check if time limit reached
                if elapsed >= target_duration:
                    log_event(f"Service {name} completed duration {format_time(elapsed)}")
                    # Kill the process group
                    try:
                        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                        try:
                            p.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    except Exception as e:
                        log_event(f"Error stopping {name}: {e}")
                        
                    crash_count = get_crash_count(p_info["dir"])
                    reproduced_count = 0
                    if crash_count > 0:
                        log_event(f"Running auto_crash_check -r for {name} (crashes: {crash_count})")
                        subprocess.run([sys.executable, str(AUTO_CRASH_CHECK), "-r", name], cwd=str(WORKSPACE_ROOT), check=False)
                        reproduced_count = get_reproduced_count(p_info["dir"])
                        log_event(f"Reproduced crashes for {name}: {reproduced_count}")
                    update_service_status(
                        name,
                        'stop',
                        {
                            "duration": elapsed,
                            "status": "completed",
                            "crash_num": crash_count,
                            "start_time": start_t,
                            "reproduced_num": reproduced_count,
                        },
                    )
                    finished_pids.append(pid)

            # Remove finished processes from tracking
            for pid in finished_pids:
                del running_processes[pid]

            # 2. Start new processes if slots available
            while len(running_processes) < max_concurrent and service_queue:
                next_service_name = service_queue.pop(0)
                
                if next_service_name not in service_dirs:
                    log_event(f"Service directory not found for {next_service_name}, skipping.")
                    continue
                    
                service_dir = service_dirs[next_service_name]
                run_script = service_dir / "run.sh"
                
                target_duration = durations_by_service.get(next_service_name, default_duration_seconds)
                log_event(
                    f"Launching {next_service_name} with target {format_time(target_duration)}..."
                )
                try:
                    p = subprocess.Popen(
                        ["/bin/bash", str(run_script)],
                        cwd=str(service_dir),
                        preexec_fn=os.setsid,
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL
                    )
                    running_processes[p.pid] = {
                        "name": next_service_name,
                        "process": p,
                        "start_time": time.time(),
                        "dir": service_dir,
                        "target_duration": target_duration,
                    }
                    update_service_status(next_service_name, 'start')
                except Exception as e:
                    log_event(f"Failed to launch {next_service_name}: {e}")
                    update_service_status(next_service_name, 'stop', {"duration": 0, "status": f"launch_failed: {e}"})

            # 3. Status update (Simple Log)
            # Log is handled by log_message directly
            
            if len(running_processes) == 0 and len(service_queue) == 0:
                break
                
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Stopping all services...")
        for pid, p_info in running_processes.items():
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except:
                pass
        print("[*] Cleanup complete.")

    print("\n[*] Batch execution finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run multiple fuzzing services in parallel.")
    parser.add_argument("--duration", type=str, default="1h", help="Duration per service (e.g., '24h', '30m'). Default: 1h")
    parser.add_argument("--concurrent", type=int, default=2, help="Max concurrent services. Default: 2")
    
    args = parser.parse_args()

    # Check for sudo/root
    if os.geteuid() != 0:
        print("Error: This script must be run with sudo because the underlying run.sh scripts require it.")
        print(f"Usage: sudo python3 {sys.argv[0]} [args]")
        sys.exit(1)

    try:
        duration_seconds = parse_duration(args.duration)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Load services from JSON
    target_services_names = load_service_queue()
    
    if not target_services_names:
        print("No services found in service_fuzz.json.")
        sys.exit(1)

    # Derive per-service durations from success id counts when available.
    success_hours = load_success_hours()
    durations_by_service = {}
    for name in target_services_names:
        hours = success_hours.get(name)
        if hours is None:
            continue
        durations_by_service[name] = max(0, min(int(hours), 24)) * 3600

    run_batch(
        target_services_names,
        duration_seconds,
        args.concurrent,
        durations_by_service=durations_by_service,
    )
