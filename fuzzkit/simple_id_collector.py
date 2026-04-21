import os
import json

def collect_simple_ids():
    # Determine paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    workspace_root = os.path.dirname(script_dir)
    mig_services_dir = os.path.join(workspace_root, 'mig_services')
    output_file = os.path.join(script_dir, 'simple_ids.json')
    
    simple_ids_map = {}
    
    if not os.path.exists(mig_services_dir):
        print(f"Error: mig_services directory not found at {mig_services_dir}")
        return

    # Iterate over each item in mig_services directory
    for service_name in os.listdir(mig_services_dir):
        service_path = os.path.join(mig_services_dir, service_name)
        
        # Check if it is a directory
        if not os.path.isdir(service_path):
            continue
            
        form_cons_path = os.path.join(service_path, 'form_cons.json')
        
        # Check if form_cons.json exists
        if not os.path.exists(form_cons_path):
            continue
            
        try:
            with open(form_cons_path, 'r') as f:
                data = json.load(f)
                
            service_simple_ids = []
            
            for msg_id, msg_data in data.items():
                # Navigate to identified_descriptors
                try:
                    descriptors = msg_data.get('stage3_structure_location', {}) \
                                          .get('descriptor_analysis', {}) \
                                          .get('identified_descriptors')
                    
                    # Check if descriptors is an empty list
                    if descriptors is not None and isinstance(descriptors, list) and len(descriptors) == 0:
                        # Convert msg_id to int if possible, otherwise keep as string
                        try:
                            service_simple_ids.append(int(msg_id))
                        except ValueError:
                            service_simple_ids.append(msg_id)
                            
                except Exception as e:
                    print(f"Error processing message {msg_id} in {service_name}: {e}")
                    continue
            
            if service_simple_ids:
                # Sort for consistency
                service_simple_ids.sort(key=lambda x: int(x) if isinstance(x, int) else x)
                simple_ids_map[service_name] = service_simple_ids
                
        except json.JSONDecodeError:
            print(f"Error decoding JSON in {form_cons_path}")
        except Exception as e:
            print(f"Unexpected error processing {service_name}: {e}")

    # Save results
    try:
        with open(output_file, 'w') as f:
            json.dump(simple_ids_map, f, indent=2)
        print(f"Successfully saved simple IDs to {output_file}")
        print(f"Found simple IDs for {len(simple_ids_map)} services.")
    except Exception as e:
        print(f"Error saving output file: {e}")

if __name__ == "__main__":
    collect_simple_ids()
