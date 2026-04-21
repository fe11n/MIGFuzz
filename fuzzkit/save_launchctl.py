#!/usr/bin/env python3
"""
Script to save launchctl print output for all services in fuzz_exec to their respective directories.
"""

import os
import subprocess
import sys
from pathlib import Path

def main():
    workspace_dir = Path(__file__).parent
    fuzz_exec_dir = workspace_dir / 'fuzz_exec'
    
    if not fuzz_exec_dir.exists():
        print(f"fuzz_exec directory not found: {fuzz_exec_dir}")
        sys.exit(1)
    
    for service_dir in fuzz_exec_dir.iterdir():
        if not service_dir.is_dir():
            continue
        
        service_name = service_dir.name
        launchctl_file = service_dir / 'launchctl.txt'
        
        print(f"Processing {service_name}...")
        
        # Run launchctl print
        cmd = ['launchctl', 'print', f'system/{service_name}']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout
            if result.returncode != 0:
                # Try user domain if system fails
                import getpass
                uid = os.getuid()
                cmd_user = ['launchctl', 'print', f'gui/{uid}/{service_name}']
                result_user = subprocess.run(cmd_user, capture_output=True, text=True, timeout=10)
                if result_user.returncode == 0:
                    output = result_user.stdout
                    print(f"  Found in user domain (gui/{uid})")
                else:
                    print(f"  Failed to get launchctl info for {service_name}: {result.stderr.strip()}")
                    continue
        except subprocess.TimeoutExpired:
            print(f"  Timeout for {service_name}")
            continue
        except Exception as e:
            print(f"  Error for {service_name}: {e}")
            continue
        
        # Write to file
        try:
            with open(launchctl_file, 'w') as f:
                f.write(output)
            print(f"  Saved to {launchctl_file}")
        except Exception as e:
            print(f"  Failed to write file for {service_name}: {e}")

if __name__ == "__main__":
    main()