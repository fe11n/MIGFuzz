import json
import subprocess
import os
import multiprocessing
from functools import partial

INPUT_FILE = 'mig_services/communication_stats.json'

def check_root(service_name):
    """
    Check if a service is accessible via 'launchctl print system/<service_name>'.
    Returns (service_name, is_root)
    """
    try:
        # Suppress output to keep terminal clean
        result = subprocess.run(
            ['launchctl', 'print', f'system/{service_name}'],
            capture_output=True,
            text=True
        )
        return service_name, result.returncode == 0
    except Exception:
        return service_name, False

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, 'r') as f:
        data = json.load(f)

    # 1. Identify MIG services
    # We allow the set to handle duplicates if the JSON has them, 
    # though it's likely a list of strings.
    mig_services_set = set(data.get('MIG', []))
    
    # 2. Identify All services mentioned in the file
    all_services_set = set()
    for category, services in data.items():
        all_services_set.update(services)

    print(f"Total Unique Services in File: {len(all_services_set)}")
    print(f"Total MIG Services in File: {len(mig_services_set)}")

    # 3. Check Root Status in parallel
    # We only check valid services found in the file
    pool = multiprocessing.Pool(processes=16)
    results = pool.map(check_root, all_services_set)
    pool.close()
    pool.join()

    # Build a lookup for root status
    is_root_map = dict(results)

    # 4. Calculate Counts
    # count_mig: Total MIG services (as per file list)
    # Note: Should we only count MIG services that exist on the system?
    # The prompt implies analyzing the PROPORTION based on the classifications.
    # But determining "Root" depends on the system check.
    # If a service is in the file but not installed, it will count as Non-Root.
    # This might skew results if the file lists services not present.
    # However, strictly following "launchctl print system can find", 
    # a missing service is NOT found in system -> Not Root.
    
    count_mig_total = len(mig_services_set)
    
    root_services_set = {s for s, is_root in is_root_map.items() if is_root}
    count_root_total = len(root_services_set)
    
    # Intersection: MIG services that are Root
    mig_root_intersection = mig_services_set.intersection(root_services_set)
    count_mig_root = len(mig_root_intersection)

    print(f"Total Root Services (found on system): {count_root_total}")
    print(f"MIG & Root Intersection: {count_mig_root}")

    # 5. Calculate Ratios
    # Ratio 1: P(Root | MIG)
    if count_mig_total > 0:
        ratio_root_given_mig = count_mig_root / count_mig_total
        print(f"Ratio 1: MIG Service is Root (Root / Total MIG): {ratio_root_given_mig:.2%}")
    else:
        print("Ratio 1: Undefined")

    # Ratio 2: P(MIG | Root)
    if count_root_total > 0:
        ratio_mig_given_root = count_mig_root / count_root_total
        print(f"Ratio 2: Root Service is MIG (MIG_Root / Total Root): {ratio_mig_given_root:.2%}")
    else:
        print("Ratio 2: Undefined")

if __name__ == "__main__":
    main()
