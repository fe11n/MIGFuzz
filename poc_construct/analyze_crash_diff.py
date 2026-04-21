import argparse
import json
import os
import subprocess
import sys
import re

def get_service_endpoint(service_name):
    json_path = os.path.join(os.path.dirname(__file__), 'service_endpoints.json')
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                mapping = json.load(f)
            return mapping.get(service_name, service_name)
        except:
            pass
    return service_name

def parse_header_bytes(lines):
    # Expecting lines of hex bytes
    hex_str = ""
    for line in lines:
        parts = line.strip().split()
        for p in parts:
            if p.startswith("0x"):
                hex_str += p[2:]
    return hex_str

def parse_body_bytes(lines):
    # Expecting lines of hex bytes
    hex_str = ""
    for line in lines:
        parts = line.strip().split()
        for p in parts:
            if p.startswith("0x"):
                hex_str += p[2:]
    return hex_str

def get_messages_from_binary_output(output):
    messages = []
    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "=== Sending Generated Message ===" in line or "=== Sending Custom Message ===" in line:
            msg = {"header_bytes": "", "body_bytes": "", "header_info": {}}
            i += 1
            while i < len(lines):
                line = lines[i]
                if "=== Sending Generated Message ===" in line or "=== Sending Custom Message ===" in line:
                    break # Next message
                
                if "------ MACH MSG HEADER ------" in line:
                    i += 1
                    while i < len(lines) and "------" not in lines[i]:
                        if ":" in lines[i]:
                            key, val = lines[i].split(":", 1)
                            msg["header_info"][key.strip()] = val.strip()
                        i += 1
                    continue

                if "------ MACH MSG HEADER IN BYTES ------" in line:
                    i += 1
                    header_lines = []
                    while i < len(lines) and "------" not in lines[i]:
                        header_lines.append(lines[i])
                        i += 1
                    msg["header_bytes"] = parse_header_bytes(header_lines)
                    continue

                if "------ MACH MSG BODY IN BYTES" in line:
                    i += 1
                    body_lines = []
                    while i < len(lines) and "Message sent successfully" not in lines[i] and "Failed to send message" not in lines[i] and "=== Sending" not in lines[i] and "Dryrun" not in lines[i] and "dryrun" not in lines[i]:
                        body_lines.append(lines[i])
                        i += 1
                    msg["body_bytes"] = parse_body_bytes(body_lines)
                    continue
                
                i += 1
            messages.append(msg)
        else:
            i += 1
    return messages

def run_reproduce(script_name, args):
    script_path = os.path.join(os.path.dirname(__file__), script_name)
    cmd = [sys.executable, script_path] + args
    try:
        result = subprocess.run(cmd, cwd=os.path.dirname(__file__), capture_output=True, text=True)
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

def parse_crash_path(crash_path):
    abs_path = os.path.abspath(crash_path)
    parts = abs_path.split(os.sep)
    
    try:
        if 'fuzz_exec' in parts:
            fuzz_exec_idx = parts.index('fuzz_exec')
            service_name = parts[fuzz_exec_idx + 1]
        else:
            raise ValueError("Path does not contain 'fuzz_exec'")
            
        crash_name = os.path.basename(abs_path)
        return service_name, crash_name, abs_path
    except (ValueError, IndexError) as e:
        print(f"Error: Could not parse service name from path: {crash_path}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Analyze crash difference between message log and generator.")
    parser.add_argument("crash_path", help="Path to the crash sample file")
    args = parser.parse_args()

    service_name, crash_file_name, crash_file_path = parse_crash_path(args.crash_path)
    # Check json paths
    service_dir = os.path.dirname(os.path.dirname(os.path.dirname(crash_file_path)))
    json_path = os.path.join(service_dir, "message_content.json")
    
    # 1. Load json to update conwith_generator
    target_entry = None
    all_data = []

    if os.path.exists(json_path):
        with open(json_path, 'r') as f:
            all_data = json.load(f)
            for entry in all_data:
                if crash_file_name in entry['filename']:
                    target_entry = entry
                    break
    
    has_target_entry = target_entry is not None

    # 2. Run reproduce scripts to get live outputs
    bymessage_stdout, bymessage_stderr, bymessage_rc = run_reproduce(
        "reproduce_crash_bymessage.py",
        ["-a", "--dry-run", crash_file_path]
    )
    bygenerator_stdout, bygenerator_stderr, bygenerator_rc = run_reproduce(
        "reproduce_crash_bygenerator.py",
        ["-v", "--dry-run", "--no-build", crash_file_path]
    )

    expected_messages = get_messages_from_binary_output(bymessage_stdout)
    actual_messages = get_messages_from_binary_output(bygenerator_stdout)
    
    # print(f"\nFound {len(expected_messages)} expected messages and {len(actual_messages)} actual messages.")

    match_count = 0
    total_expected = len(expected_messages)
    
    # Update conwith_generator flag
    consistent = True
    results = []
    
    compare_count = min(len(expected_messages), len(actual_messages))
    if len(expected_messages) != len(actual_messages):
        results.append(f"Message count mismatch (ignored): expected {len(expected_messages)}, actual {len(actual_messages)}")

    for idx in range(compare_count):
        exp = expected_messages[idx]
        act = actual_messages[idx]

        exp_header_info = exp['header_info']
        act_header_info = act['header_info']
        exp_id = exp_header_info.get('msg_id', 'Unknown')
        act_id = act_header_info.get('msg_id', 'Unknown')

        exp_body = exp['body_bytes']
        act_body = act['body_bytes']
        exp_size = len(exp_body) // 2
        act_size = len(act_body) // 2

        status = "OK"
        if exp_id != act_id:
            consistent = False
            status = f"ID mismatch - expected {exp_id}, actual {act_id}"

        if exp_size != act_size:
            consistent = False
            if status == "OK":
                status = f"Body length mismatch - expected {exp_size}, actual {act_size}"
            else:
                status = status + f"; Body length mismatch - expected {exp_size}, actual {act_size}"

        results.append(
            f"Message {idx}: {status} | id: {exp_id} vs {act_id} | size: {exp_size} vs {act_size}"
        )

    # Update message_content.json if entry exists
    if has_target_entry:
        target_entry['conwith_generator'] = consistent
        with open(json_path, 'w') as f:
            json.dump(all_data, f, indent=4)

    # Print all comparison results
    print("Message comparison results:")
    for res in results:
        print(res)

    # Print result for caller to capture
    print(f"CONWITH_GENERATOR:{str(consistent).lower()}")

if __name__ == "__main__":
    main()
