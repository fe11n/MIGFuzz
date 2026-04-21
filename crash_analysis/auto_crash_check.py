#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from reproduce_crash import reproduce_crashes

def main():
    parser = argparse.ArgumentParser(description="Auto crash check script")
    parser.add_argument('target_service', nargs='?', help='Target service name (optional)')
    parser.add_argument('-r', '--reproduce', action='store_true', help='Reproduce and verify crashes')
    args = parser.parse_args()

    # Change to crash_analysis directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Get all crash sample paths and count
    fuzz_exec_dir = script_dir.parent / 'fuzz_exec'

    # Determine target user and group
    target_uid = os.getuid()
    target_gid = os.getgid()
    if 'SUDO_UID' in os.environ:
        target_uid = int(os.environ['SUDO_UID'])
        target_gid = int(os.environ['SUDO_GID'])

    service_names = []
    counts = []
    crash_samples = []

    for service_dir in fuzz_exec_dir.iterdir():
        if not service_dir.is_dir():
            continue
        service_name = service_dir.name
        if args.target_service and service_name != args.target_service:
            continue

        # Change ownership to normal user
        subprocess.run(['sudo', 'chown', '-R', f'{target_uid}:{target_gid}', str(service_dir)], check=False)

        crashes_dir = service_dir / 'out' / 'crashes'
        if not crashes_dir.exists():
            continue

        count = 0
        for crash_file in crashes_dir.iterdir():
            if not crash_file.is_file():
                continue
            if crash_file.name == 'crash_check_result.json':
                continue
            if crash_file.name.endswith('.log'):
                continue

            # Check if already in icrashes
            icrashes_dir = service_dir / 'out' / 'icrashes'
            if icrashes_dir.exists() and (icrashes_dir / crash_file.name).exists():
                continue

            # Check if already processed in crash_check_result.json
            results_json_path = crashes_dir / 'crash_check_result.json'
            if results_json_path.exists():
                try:
                    import json
                    with open(results_json_path, 'r') as f:
                        results_data = json.load(f)
                        if crash_file.name in results_data:
                            continue
                except Exception:
                    pass

            crash_samples.append(crash_file)
            count += 1

        if count > 0:
            service_names.append(service_name)
            counts.append(count)

    # Print summary
    print(f"Discovered {len(service_names)} services:")
    for name, count in zip(service_names, counts):
        print(f"  {name}: {count} samples")
    print()

    # Variables to track processed files to avoid duplication
    processed_files = set()
    results = []

    def get_crash_signature(filename):
        clean_name = filename
            
        parts = clean_name.split('_')
        address_index = -1
        for i, part in enumerate(parts):
            if part.startswith('0x'):
                address_index = i
                break
        
        if address_index != -1:
            # 地址前的字符串
            prefix = '_'.join(parts[:address_index])
            # 第一个地址
            address = parts[address_index]
            return prefix, address
        return None, None

    # Process each sample
    for crash_path in crash_samples:
        if str(crash_path) in processed_files:
            continue
            
        service = crash_path.parent.parent.parent.name
        crash_file = crash_path.name

        print(f"Processing: {service} / {crash_file}")

        # Run python script with retries
        max_retries = 5
        is_crash = False
        crash_in_module = False
        output = ""

        for attempt in range(max_retries):
            cmd = [sys.executable, 'crash_check_validation.py', '--verbose', str(crash_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout + result.stderr
            
            # Reset for this attempt
            current_is_crash = False
            current_crash_in_module = False
            
            # Extract values
            for line in output.split('\n'):
                if line.startswith('is_crash:'):
                    current_is_crash = line.split(':')[1].strip() == 'True'
                elif line.startswith('crash_in_module:'):
                    current_crash_in_module = line.split(':')[1].strip() == 'True'
            
            if current_is_crash:
                is_crash = current_is_crash
                crash_in_module = current_crash_in_module
                break
            
            print(f"  Attempt {attempt + 1}/{max_retries} failed (is_crash=False).")

        print(f"is_crash: {is_crash}")
        print(f"crash_in_module: {crash_in_module}")
        print()

        # Update crash_check_result.json
        crashes_dir = crash_path.parent
        results_json_path = crashes_dir / 'crash_check_result.json'
        results_data = {}
        if results_json_path.exists():
            try:
                import json
                with open(results_json_path, 'r') as f:
                    results_data = json.load(f)
            except Exception:
                pass
        
        results_data[crash_file] = {
            "is_crash": is_crash,
            "crash_in_module": crash_in_module,
            "output": output
        }
        
        with open(results_json_path, 'w') as f:
            import json
            json.dump(results_data, f, indent=4)

        # Save output to log file
        log_file = crash_path.with_suffix('.log')
        log_file.write_text(output)

        # Determine action
        if is_crash and crash_in_module:
            icrashes_dir = crash_path.parent.parent / 'icrashes'
            icrashes_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy(crash_path, icrashes_dir / crash_file)
            log_file = icrashes_dir / f"{crash_file}.log"
            log_file.write_text(output)
            
            results.append(f"{service}|{crash_file}|{is_crash}|{crash_in_module}")
            processed_files.add(str(crash_path))
            
            # Search for similar crashes
            curr_prefix, curr_address = get_crash_signature(crash_file)
            if curr_prefix is not None:
                crashes_dir = crash_path.parent
                for other_file in crashes_dir.iterdir():
                    if not other_file.is_file() or other_file.name.endswith('.log'):
                        continue
                    
                    # Skip the current file itself
                    if other_file.resolve() == crash_path.resolve():
                        continue
                        
                    other_prefix, other_address = get_crash_signature(other_file.name)
                    if other_prefix == curr_prefix and other_address == curr_address:
                        # Found similar crash
                        target_name = other_file.name
                        
                        # Copy to icrashes
                        shutil.copy(other_file, icrashes_dir / target_name)
                        print(f"  -> Auto-match: Found similar crash {other_file.name}. Copied to icrashes as {target_name}.")
                        
                        # Mark as processed if it's in our main list
                        processed_files.add(str(other_file))
                        results.append(f"{service}|{target_name}|True|True (Auto-match)")
                        
                        # Update JSON for similar crash
                        results_data[target_name] = {
                            "is_crash": True,
                            "crash_in_module": True,
                            "output": "Auto-match with " + crash_file
                        }
                        with open(results_json_path, 'w') as f:
                            json.dump(results_data, f, indent=4)

        else:
            results.append(f"{service}|{crash_file}|{is_crash}|{crash_in_module}")
            processed_files.add(str(crash_path))

    # Final summary

    # Final summary
    print("Final Results:")
    print("Service | Crash File | Is Crash | Crash in Module")
    print("--------|------------|----------|----------------")
    for result in results:
        print(result.replace('|', ' | '))

    if args.reproduce:
        print("\nStarting Crash Reproduction and Verification...")
        mig_services_dir = script_dir.parent / 'mig_services'
        reproduce_script = script_dir.parent / 'poc_construct' / 'reproduce_crash_bymessage.py'
        poc_construct_dir = script_dir.parent / 'poc_construct'

        reproduce_crashes(
            fuzz_exec_dir=fuzz_exec_dir,
            mig_services_dir=mig_services_dir,
            target_service=args.target_service,
            target_uid=target_uid,
            reproduce_script=reproduce_script,
            poc_construct_dir=poc_construct_dir,
        )

if __name__ == "__main__":
    main()