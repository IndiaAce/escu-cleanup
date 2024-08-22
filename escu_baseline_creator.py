import os
import yaml
import re

# SOME SAMPLE TTPS TO TEST WITH T1059.001 & T1556 

EXCLUDED_MACROS = [
    r"nh-aw_shadow_package",
    r"nh-aw_macro_placeholder",
    r"security_content_ctime\(firstTime\)",
    r"security_content_ctime\(lastTime\)",
    r"drop_dm_object_name\(.+\)"
]

def snake_case(string):
    return re.sub(r'\W|^(?=\d)', "_", string).lower()

def validate_mitre_id(mitre_id):
    """Validate the MITRE ID format."""
    if re.match(r'^T\d{4}(\.\d{3})?$', mitre_id):
        return True
    return False

def load_detections(repo_path, mitre_id):
    detections = []
    subdirectories = ['application', 'cloud', 'endpoint', 'network', 'web']
    
    for subdir in subdirectories:
        subdir_path = os.path.join(repo_path, 'detections', subdir)
        for root, _, files in os.walk(subdir_path):
            for file in files:
                if file.endswith('.yml'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        try:
                            detection = yaml.safe_load(f)
                        except yaml.YAMLError as exc:
                            print(f"Error parsing YAML file {file_path}: {exc}")
                            continue
                        
                        # Access mitre_attack_id inside the 'tags' field
                        if 'tags' in detection and 'mitre_attack_id' in detection['tags']:
                            mitre_ids = detection['tags']['mitre_attack_id']
                            
                            # Check if the specified MITRE TTP ID is in the list
                            if mitre_id in mitre_ids:
                                obfuscated_path = f"C:\\mothership\\command-center\\dev_link\\splunk_dev\\escu-baseline\\security_content\\detections\\{file}"
                                print(f"Matched file: {obfuscated_path}")  # Output obfuscated file paths
                                detections.append(detection)
    return detections

def save_detections_to_yaml(detections, output_file):
    # Ensure the directory exists
    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_file, 'w') as f:
        for detection_id, content in detections.items():
            # Write id and title (matching each other)
            f.write(f"id: {detection_id}\n")
            f.write(f"title: {detection_id}\n")
            f.write(f"catalog_type: correlation_search\n")
            
            # Write mitre_attack_id if present
            mitre_ids = content.get('mitre_attack_id', [])
            if mitre_ids:
                f.write(f"mitre_attack_id:\n")
                for mitre_id in mitre_ids:
                    f.write(f"  - {mitre_id}\n")
            
            # Write authorization_scope and throttle_timeframe
            f.write(f"authorization_scope: detection\n")
            f.write(f"throttle_timeframe: 14400s\n")
            
            # Write description
            description = content.get('description', '')
            if description:
                f.write(f"description: {description}\n")
            
            # Write tuning_macros (you might need to customize this)
            f.write(f"tuning_macros:\n")
            f.write(f"  - {detection_id}_filter\n")
            
            # Replace observable with suppress_fields (first value)
            observables = content.get('observable', [])
            if observables:
                suppress_field = observables[0].get('name', '')
                f.write(f"suppress_fields:\n")
                f.write(f"  - {suppress_field}\n")
            
            # Write required_fields
            required_fields = content.get('required_fields', [])
            if required_fields:
                f.write(f"required_fields:\n")
                for field in required_fields:
                    f.write(f"  - {field}\n")
            
            # Write the search content, renamed to "content" and formatted
            search_content = content.get('search', '')
            if search_content:
                f.write(f"content: >\n")
                search_lines = search_content.strip().split(' | ')
                for line in search_lines:
                    f.write(f"  | {line.strip()}\n")
    
    print(f"\nDetections saved to {output_file}")




# THIS IS NEW PLEASE REMOVE IT IF IT BREAKS ANYTHING 
# I'M SO SCARED THIS IS GOING TO BREAK EVERYTHING

def create_logic_filter_file(macro_name, logic_filter_dir):
    # Sanitize the macro name to make it a valid file name
    sanitized_macro_name = re.sub(r'[\\/*?:"<>|]', "_", macro_name)
    logic_filter_file = os.path.join(logic_filter_dir, f"{sanitized_macro_name}.yml")
    
    # Prepare the logic filter content
    logic_filter_content = {
        'id': f"{sanitized_macro_name}",
        'catalog_type': "macro",
        'content': "empty macro for tuning"
    }

    # Write the logic filter content to the YAML file in the desired order
    with open(logic_filter_file, 'w') as f:
        f.write(f"- id: {logic_filter_content['id']}\n")
        f.write(f"  catalog_type: {logic_filter_content['catalog_type']}\n")
        f.write(f"  content: >\n")
        f.write(f"    ```{logic_filter_content['content']}```\n")
    
    print(f"Created logic filter YML file: {logic_filter_file}")

def create_historical_baseline_file(escu_id, title, description, content, output_dir):
    file_path = os.path.join(output_dir, f"{escu_id}_historical_baseline.yml")
    
    baseline_content = {
        'id': f"{escu_id}_historical_baseline_search",
        'title': title,
        'catalog_type': "search",
        'description': description,
        'authorization_scope': "detection",
        'content': content
    }

    # Write the baseline content to the YAML file in the desired order
    with open(file_path, 'w') as f:
        f.write(f"- id: {baseline_content['id']}\n")
        f.write(f"  title: {baseline_content['title']}\n")
        f.write(f"  catalog_type: {baseline_content['catalog_type']}\n")
        f.write(f"  description: {baseline_content['description']}\n")
        f.write(f"  authorization_scope: {baseline_content['authorization_scope']}\n")
        f.write(f"  content: >\n")
        f.write(f"    {baseline_content['content']}\n")
    
    print(f"Created historical baseline YML file: {file_path}")

def create_correlation_search_file(escu_id, title, description, mitre_attack_ids, tuning_macros, suppress_fields, required_fields, content, output_dir):
    file_path = os.path.join(output_dir, f"{escu_id}.yml")
    
    correlation_search_content = {
        'id': escu_id,
        'title': title,
        'catalog_type': "correlation_search",
        'description': description,
        'mitre_attack_id': mitre_attack_ids,
        'authorization_scope': "detection",
        'throttle_timeframe': "14400s",
        'tuning_macros': tuning_macros,
        'suppress_fields': suppress_fields,
        'required_fields': required_fields,
        'content': content
    }

    # Write the correlation search content to the YAML file in the desired order
    with open(file_path, 'w') as f:
        f.write(f"- id: {correlation_search_content['id']}\n")
        f.write(f"  title: {correlation_search_content['title']}\n")
        f.write(f"  catalog_type: {correlation_search_content['catalog_type']}\n")
        f.write(f"  description: >\n    {correlation_search_content['description']}\n")
        f.write(f"  mitre_attack_id:\n")
        for mitre_id in correlation_search_content['mitre_attack_id']:
            f.write(f"    - {mitre_id}\n")
        f.write(f"  authorization_scope: {correlation_search_content['authorization_scope']}\n")
        f.write(f"  throttle_timeframe: {correlation_search_content['throttle_timeframe']}\n")
        f.write(f"  tuning_macros:\n")
        for macro in correlation_search_content['tuning_macros']:
            f.write(f"    - {macro}\n")
        f.write(f"  suppress_fields:\n")
        for field in correlation_search_content['suppress_fields']:
            f.write(f"    - {field}\n")
        f.write(f"  required_fields:\n")
        for field in correlation_search_content['required_fields']:
            f.write(f"    - {field}\n")
        f.write(f"  content: >\n    {correlation_search_content['content']}\n")
    
    print(f"Created correlation search YML file: {file_path}")




def replace_macros_in_search(search_query, macro_dir, logic_filter_dir):
    def replace_macro(match):
        macro_name = match.group(1)

        # Check if the macro matches any of the exclusion patterns
        for pattern in EXCLUDED_MACROS:
            if re.match(pattern, macro_name):
                return f'`{macro_name}`'

        # Continue with replacement logic if not excluded
        macro_file = os.path.join(macro_dir, f"{macro_name}.yml")
        if os.path.exists(macro_file):
            with open(macro_file, 'r') as f:
                macro_content = yaml.safe_load(f)
                definition = macro_content.get('definition', '')
                return definition
        else:
            create_logic_filter_file(macro_name, logic_filter_dir)
            return f"`{macro_name}` ```Macro not found in Macros```"

    # Replace all macros in the search_query using the regex pattern
    return re.sub(r'`([^`]+)`', replace_macro, search_query)


def organize_detections_by_id(detections, fields, macro_dir, logic_filter_dir, output_dir):
    escu_detections_dir = r"C:\Users\lukew\OneDrive\Documents\dev_link\splunk_dev\escu-baseline\ESCU_Detections"
    
    for detection in detections:
        name_snake_case = snake_case(detection['name'])
        detection_id = f"nh-aw_escu_{name_snake_case}"
        
        # Determine which type of YAML file to create based on the fields in the detection
        if 'historical_baseline' in detection['name'].lower():
            create_historical_baseline_file(
                escu_id=detection_id,
                title=detection['name'],
                description=detection.get('description', ''),
                content=detection.get('search', ''),
                output_dir=escu_detections_dir
            )
        
        elif 'correlation_search' in detection['tags'].get('catalog_type', '').lower():
            create_correlation_search_file(
                escu_id=detection_id,
                title=detection['name'],
                description=detection.get('description', ''),
                mitre_attack_ids=detection['tags'].get('mitre_attack_id', []),
                tuning_macros=[f"{detection_id}_filter"],  # Assuming filter macros are named after the detection ID
                suppress_fields=[detection.get('observable', [])[0]['name']],  # First observable field as suppress_field
                required_fields=detection.get('required_fields', []),
                content=replace_macros_in_search(detection.get('search', ''), macro_dir, logic_filter_dir),
                output_dir=escu_detections_dir
            )
        
        elif 'macro' in detection['tags'].get('catalog_type', '').lower():
            # Handle macros specifically
            create_logic_filter_file(name_snake_case, logic_filter_dir)

        else:
            organized_detections = {}
            organized_detections[detection_id] = {
                'name': detection['name'],
                'description': detection.get('description', ''),
                'mitre_attack_id': detection['tags'].get('mitre_attack_id', []),
                'observable': detection.get('observable', []),
                'required_fields': detection.get('required_fields', []),
                'search': detection.get('search', '')
            }
            
            # Save detections to the specified output directory
            save_detections_to_yaml(organized_detections, os.path.join(escu_detections_dir, f"{detection_id}.yml"))


def main():
    # Adjust this path to the actual path where your security_content directory is located
    repo_path = r"C:\Users\lukew\OneDrive\Documents\dev_link\splunk_dev\escu-baseline\security_content"
    
    # Path to the directory containing the macros
    macro_directory = r"C:\Users\lukew\OneDrive\Documents\dev_link\splunk_dev\escu-baseline\security_content\macros"
    
    # Path to the directory where logic filter YML files should be saved
    logic_filter_dir = r"C:\Users\lukew\OneDrive\Documents\dev_link\splunk_dev\escu-baseline\ESCU_Macros"
    
    # Path to the directory where the final YAML files should be saved
    output_dir = r"C:\Users\lukew\OneDrive\Documents\dev_link\splunk_dev\escu-baseline\output"
    
    # Prompt the user to enter a MITRE TTP ID
    mitre_id = input("Enter the MITRE TTP ID (e.g., T1003 or T1003.001): ").strip()
    
    # Validate the MITRE ID format
    if not validate_mitre_id(mitre_id):
        print("Error: Invalid MITRE TTP ID format. Please use TXXXX or TXXXX.XXX format.")
        return
    
    # Default fields to return
    default_fields = ['name', 'description', 'search', 'mitre_attack_id', 'observable', 'required_fields']

    detections = load_detections(repo_path, mitre_id)
    if not detections:
        print(f"No detections found for MITRE TTP ID: {mitre_id}")
        return

    # Pass the macro directory, logic filter directory, and output directory to the organize_detections_by_id function
    organize_detections_by_id(detections, default_fields, macro_directory, logic_filter_dir, output_dir)

    print("\nAll matched detections processed and saved successfully.")



if __name__ == "__main__":
    main()