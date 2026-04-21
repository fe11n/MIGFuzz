#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import shutil
import sys
import argparse
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from llm_utils.utils import log_message, SERVICES_DIR, FUZZ_EXEC_DIR

def clean_service_data(service_name: str):
    """
    Clears generated data for a specific service.
    Targets:
    1. mig_services/{service}/constraints
    2. fuzz_exec/{service}/functions
    3. fuzz_exec/{service}/check_result.json
    """
    log_message(f"Starting cleanup for service: {service_name}")
    
    # 1. Clear mig_services/{service}/constraints
    service_dir = SERVICES_DIR / service_name
    constraints_dir = service_dir / "constraints"
    
    if constraints_dir.exists():
        try:
            shutil.rmtree(constraints_dir)
            log_message(f"Removed: {constraints_dir}")
        except Exception as e:
            log_message(f"Failed to remove {constraints_dir}: {e}")
    else:
        log_message(f"Not found (skipped): {constraints_dir}")

    # 2. Clear fuzz_exec/{service}/functions
    exec_dir = FUZZ_EXEC_DIR / service_name
    functions_dir = exec_dir / "functions"
    
    if functions_dir.exists():
        try:
            shutil.rmtree(functions_dir)
            log_message(f"Removed: {functions_dir}")
        except Exception as e:
            log_message(f"Failed to remove {functions_dir}: {e}")
    else:
        log_message(f"Not found (skipped): {functions_dir}")

    # 3. Remove fuzz_exec/{service}/check_result.json
    check_result_file = exec_dir / "check_result.json"
    
    if check_result_file.exists():
        try:
            check_result_file.unlink()
            log_message(f"Removed: {check_result_file}")
        except Exception as e:
            log_message(f"Failed to remove {check_result_file}: {e}")
    else:
        log_message(f"Not found (skipped): {check_result_file}")
        
    log_message(f"Cleanup finished for {service_name}")

def main():
    parser = argparse.ArgumentParser(description='Clear generated constraints and functions for services.')
    parser.add_argument('services', nargs='+', help='List of service names to clean')
    
    args = parser.parse_args()
    
    for service in args.services:
        clean_service_data(service)

if __name__ == "__main__":
    main()
