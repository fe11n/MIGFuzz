#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import json

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def parse_crash_path(crash_path):
    """
    Parses the crash path to extract service name and crash name.
    Assumes path structure: .../fuzz_exec/{service_name}/out/icrashes/{crash_name}
    """
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

def get_service_endpoint(service_folder):
    json_path = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'service_endpoints.json')
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                mapping = json.load(f)
            return mapping.get(service_folder, service_folder)
        except json.JSONDecodeError:
            pass
    return service_folder

def build_send_poc(service_name):
    service_dir = os.path.join(WORKSPACE_ROOT, 'fuzz_exec', service_name)
    if not os.path.exists(service_dir):
        print(f"Error: Service directory {service_dir} does not exist.")
        return False

    generate_message_cc = os.path.join(service_dir, 'generate_message.cc')
    if not os.path.exists(generate_message_cc):
        print(f"Error: generate_message.cc not found in {service_dir}")
        return False

    cpp_file = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'send_poc_bygenerator.cpp')
    output = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'send_poc_bygenerator')

    if os.path.exists(output):
        try:
            os.remove(output)
        except OSError:
            subprocess.run(['sudo', 'rm', output])

    cmd = [
        'clang++',
        '-fno-omit-frame-pointer', '-w', '-std=c++17',
        '-I../fuzz_helpers', '-I..', f'-I../fuzz_exec/{service_name}',
        '-framework', 'Foundation',
        cpp_file,
        '../fuzz_helpers/tool_lib.cc',
        generate_message_cc,
        '-o', output
    ]

    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=os.path.join(WORKSPACE_ROOT, 'poc_construct'), check=True)
        print("Build successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        return False

def send_poc(endpoint, service_name, crash_file, verbose=False, dry_run=False, use_sudo=False):
    binary = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'send_poc_bygenerator')
    if not os.path.exists(binary):
        print(f"Error: {binary} does not exist. Please build first.")
        return False

    cmd = [binary]
    if use_sudo:
        cmd.insert(0, 'sudo')
    if verbose:
        cmd.append('-v')
    if dry_run:
        cmd.append('--dry-run')
    cmd.extend([endpoint, service_name, crash_file])

    print(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=os.path.join(WORKSPACE_ROOT, 'poc_construct'), check=True)
        print("Send successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Send failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Reproduce a crash by generating and sending PoC.")
    parser.add_argument("crash_path", help="Path to the crash sample file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Generate messages but do not send them")
    parser.add_argument("--no-build", action="store_true", help="Skip building the binary")
    parser.add_argument("--sudo", action="store_true", help="Run send_poc_bygenerator with sudo")
    args = parser.parse_args()

    service_name, crash_name, abs_crash_path = parse_crash_path(args.crash_path)
    print(f"Service: {service_name}")
    print(f"Crash Name: {crash_name}")

    endpoint = get_service_endpoint(service_name)
    print(f"Target Service Endpoint: {endpoint}")

    if not args.no_build:
        success = build_send_poc(service_name)
        if not success:
            sys.exit(1)

    success = send_poc(endpoint, service_name, abs_crash_path, args.verbose, args.dry_run, args.sudo)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()