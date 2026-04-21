#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import argparse

# Configuration
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEND_POC_BIN = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'send_poc_bymessage')
SERVICE_ENDPOINTS_JSON = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'service_endpoints.json')

def get_service_endpoint(service_folder):
    if os.path.exists(SERVICE_ENDPOINTS_JSON):
        try:
            with open(SERVICE_ENDPOINTS_JSON, 'r') as f:
                mapping = json.load(f)
            return mapping.get(service_folder, service_folder)
        except json.JSONDecodeError:
            pass
    return service_folder

def parse_crash_path(crash_path):
    """
    Parses the crash path to extract service name and crash name.
    Assumes path structure: .../fuzz_exec/{service_name}/out/icrashes/{crash_name}
    """
    abs_path = os.path.abspath(crash_path)
    parts = abs_path.split(os.sep)
    
    try:
        # Find 'fuzz_exec' and take the next component as service name
        # If 'fuzz_exec' is not in path, try to guess or fail
        if 'fuzz_exec' in parts:
            fuzz_exec_idx = parts.index('fuzz_exec')
            service_name = parts[fuzz_exec_idx + 1]
        else:
            # Fallback: assume the parent of the parent of the file is the service dir?
            # Or just fail. Let's try to be robust.
            # If path is like /tmp/crash, we can't know the service.
            # But user requirement says "can parse from crash path (like fuzz_exec/...)"
            raise ValueError("Path does not contain 'fuzz_exec'")
            
        crash_name = os.path.basename(abs_path)
        return service_name, crash_name, abs_path
    except (ValueError, IndexError) as e:
        print(f"Error: Could not parse service name from path: {crash_path}")
        sys.exit(1)

def hex_to_bytes(hex_str):
    """Convert hex string to bytes, handling both space-separated and continuous formats"""
    # Remove spaces and non-hex characters
    hex_str = ''.join(c for c in hex_str if c.isalnum())
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Invalid hex string length: {len(hex_str)}")
    try:
        return bytes(int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2))
    except ValueError as e:
        raise ValueError(f"Invalid hex value in string: {e}")

def pack_header_to_hex(header_dict):
    """Pack header dict to space-separated hex string (24 bytes, 6 uint32 fields)"""
    import struct
    fields = [
        header_dict['msgh_bits'],
        header_dict['msgh_size'],
        header_dict['msgh_remote_port'],
        header_dict['msgh_local_port'],
        header_dict['msgh_voucher_port'],
        header_dict['msgh_id']
    ]
    packed = struct.pack('<6I', *fields)  # little-endian uint32
    return ' '.join(f'{b:02x}' for b in packed)

def get_crash_content(service_name, crash_path):
    """
    Reads the crash content from message_content.json in the service folder.
    If the file doesn't exist, runs harness -v to generate it.
    """
    message_content_json = os.path.join(WORKSPACE_ROOT, 'fuzz_exec', service_name, 'message_content.json')
    
    if not os.path.exists(message_content_json):
        print("message_content.json not found. Running harness -v to generate it...")
        harness_dir = os.path.join(WORKSPACE_ROOT, 'fuzz_exec', service_name)
        harness_bin = os.path.join(harness_dir, 'harness')
        
        if not os.path.exists(harness_bin):
            print(f"Error: Harness not found at {harness_bin}")
            return []
        
        cmd = ['sudo', harness_bin, '-f', crash_path, '-v']
        print(f"Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, cwd=harness_dir, check=False, timeout=30)
        except subprocess.TimeoutExpired:
            print("Harness execution timed out.")
            return []
        except Exception as e:
            print(f"Error running harness: {e}")
            return []
        
        # Check if the file was created
        if not os.path.exists(message_content_json):
            print("Failed to generate message_content.json.")
            return []
    
    try:
        with open(message_content_json, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error parsing message_content.json: {e}")
        return []
    
    # Find the entry for the crash_path
    crash_entry = None
    for entry in data:
        if entry.get('filename') == crash_path:
            crash_entry = entry
            break
    
    if not crash_entry:
        print(f"No entry found for crash file {crash_path} in message_content.json. Running harness -v to generate it...")
        harness_dir = os.path.join(WORKSPACE_ROOT, 'fuzz_exec', service_name)
        harness_bin = os.path.join(harness_dir, 'harness')
        
        if not os.path.exists(harness_bin):
            print(f"Error: Harness not found at {harness_bin}")
            return []
        
        cmd = ['sudo', harness_bin, '-f', crash_path, '-v']
        print(f"Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, cwd=harness_dir, check=False, timeout=30)
        except subprocess.TimeoutExpired:
            print("Harness execution timed out.")
            return []
        except Exception as e:
            print(f"Error running harness: {e}")
            return []
        
        # Re-read the file after generation
        try:
            with open(message_content_json, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing updated message_content.json: {e}")
            return []
        
        # Find again
        crash_entry = None
        for entry in data:
            if entry.get('filename') == crash_path:
                crash_entry = entry
                break
        
        if not crash_entry:
            print("Still no entry found after running harness.")
            return []
    
    messages = crash_entry.get('messages', [])
    # Convert header dict to hex string
    for msg in messages:
        if 'header' in msg and isinstance(msg['header'], dict):
            msg['header'] = pack_header_to_hex(msg['header'])
        # body is already hex string
    
    return messages

def ensure_service_running(service_endpoint):
    """
    Ensures the launchd service is running. If not, starts it and prints the PID.
    """
    print(f"Checking service status for {service_endpoint}...")
    try:
        result = subprocess.run(['launchctl', 'print', f'system/{service_endpoint}'], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Failed to query service status: {result.stderr}")
            return
        output = result.stdout
        if 'state = not running' in output:
            print("Service is not running. Starting it...")
            start_result = subprocess.run(['sudo', 'launchctl', 'start', service_endpoint], capture_output=True, text=True)
            if start_result.returncode != 0:
                print(f"Failed to start service: {start_result.stderr}")
            else:
                # Extract program path from launchctl output
                import re
                program_match = re.search(r'program = (.+)', output)
                if program_match:
                    program_path = program_match.group(1).strip()
                    # Get PID
                    pgrep_result = subprocess.run(['pgrep', '-f', program_path], capture_output=True, text=True)
                    if pgrep_result.returncode == 0:
                        pid = pgrep_result.stdout.strip()
                        print(f"Service started, PID: {pid}")
                    else:
                        print("Service started, but failed to get PID.")
                else:
                    print("Service started, but could not extract program path.")
        else:
            print("Service is already running.")
    except Exception as e:
        print(f"Error checking/starting service: {e}")

def send_poc(service_endpoint, content, service_name, crash_name, dry_run=False, use_sudo=False):
    """
    Sends the PoC messages using send_poc binary.
    """
    if not os.path.exists(SEND_POC_BIN):
        print(f"Error: send_poc binary not found at {SEND_POC_BIN}")
        sys.exit(1)

    # Ensure service is running
    # ensure_service_running(service_endpoint)

    folder_path = os.path.join(WORKSPACE_ROOT, 'poc_construct', 'msg_bin', f'{service_name}_{crash_name}')
    os.makedirs(folder_path, exist_ok=True)

    for i, msg in enumerate(content):
        header_hex = msg.get('header')
        body_hex = msg.get('body', '')  # Default to empty string if missing
        
        if not header_hex:
            print(f"Skipping message {i}: missing header")
            continue

        # Convert hex to bytes
        header_bytes = hex_to_bytes(header_hex)
        body_bytes = hex_to_bytes(body_hex)

        # Save to files in the folder
        header_file_path = os.path.join(folder_path, f'header_{i}.bin')
        body_file_path = os.path.join(folder_path, f'body_{i}.bin')

        with open(header_file_path, 'wb') as f:
            f.write(header_bytes)
        with open(body_file_path, 'wb') as f:
            f.write(body_bytes)
        
        try:
            print(f"Sending message {i} to {service_endpoint}...")
            cmd = [SEND_POC_BIN, '-v']
            if dry_run:
                cmd.append('-dryrun')
            if use_sudo:
                cmd.insert(0, 'sudo')
            cmd.extend([service_endpoint, folder_path, str(i)])
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"Failed to send message {i}. Return code: {result.returncode}")
                print(f"Output: {result.stdout}")
                print(f"Error: {result.stderr}")
            else:
                print(f"Message {i} sent successfully.")
                
        except Exception as e:
            print(f"Error sending message {i}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Reproduce a crash by sending the PoC.")
    parser.add_argument("crash_path", help="Path to the crash sample file")
    parser.add_argument("--no-send", action="store_true", help="Only extract content and update json, do not send PoC")
    parser.add_argument("-a", "--all", action="store_true", help="Send all messages instead of just the last one")
    parser.add_argument("--dry-run", action="store_true", help="Construct messages but do not send them")
    parser.add_argument("--sudo", action="store_true", help="Run send_poc_bymessage with sudo")
    parser.add_argument("-f", "--force-start", action="store_true", help="Force start the service if not running")
    args = parser.parse_args()

    service_name, crash_name, abs_crash_path = parse_crash_path(args.crash_path)
    print(f"Service: {service_name}")
    print(f"Crash Name: {crash_name}")

    # Get content from message_content.json
    content = get_crash_content(service_name, abs_crash_path)
    
    if not content:
        print("Failed to get content from message_content.json.")
        sys.exit(1)

    # By default, send only the last message unless -a is specified
    if not args.all and len(content) > 1:
        print(f"Sending only the last message (total {len(content)} messages). Use -a to send all.")
        content = [content[-1]]

    # Send PoC
    if not args.no_send:
        service_endpoint = get_service_endpoint(service_name)
        print(f"Target Service Endpoint: {service_endpoint}")
        if args.force_start:
            ensure_service_running(service_endpoint)
        send_poc(service_endpoint, content, service_name, crash_name, args.dry_run, args.sudo)
    else:
        print("Skipping send_poc as --no-send was specified.")

if __name__ == '__main__':
    main()
