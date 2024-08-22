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
                                obfuscated_path = f"<FILE PATH>\\escu-baseline\\security_content\\detections\\{file}"
                                print(f"Matched file: {obfuscated_path}")  # Output obfuscated file paths
                                detections.append(detection)
    return detections

def save_detections_to_yaml(detections, output_file):
    with open(output_file, 'w') as f:
        for detection_id, content in detections.items():
            f.write(f"- id: {detection_id}\n")
            for key, value in content.items():
                if key == 'search' and value.startswith('>'):
                    f.write(f"  - {key}: >\n")
                    search_lines = value[2:].strip().split('\n')
                    for line in search_lines:
                        f.write(f"    {line.strip()}\n")
                elif isinstance(value, list):  # Handling lists like mitre_attack_id, observable, etc.
                    f.write(f"  - {key}:\n")
                    for item in value:
                        if isinstance(item, dict):
                            f.write(f"    - name: {item['name']}\n")
                            for subkey, subvalue in item.items():
                                if subkey != 'name':
                                    f.write(f"      {subkey}: {subvalue}\n")
                        else:
                            f.write(f"    - {item}\n")
                else:
                    f.write(f"  - {key}: {value}\n")
    print(f"\nDetections saved to {output_file}")

# THIS IS NEW PLEASE REMOVE IT IF IT BREAKS ANYTHING 
# I'M SO SCARED THIS IS GOING TO BREAK EVERYTHING

def create_logic_filter_file(macro_name, logic_filter_dir):
    # Sanitize the macro name to make it a valid file name
    sanitized_macro_name = re.sub(r'[\\/*?:"<>|]', "_", macro_name)
    logic_filter_file = os.path.join(logic_filter_dir, f"{sanitized_macro_name}_logic_filter.yml")
    
    # Prepare the logic filter content
    logic_filter_content = {
        'id': f"{sanitized_macro_name}_logic_filter",
        'definition': "empty macro for tuning"
    }

    # Write the logic filter content to the YAML file in the desired order
    with open(logic_filter_file, 'w') as f:
        f.write(f"- id: {logic_filter_content['id']}\n")
        f.write(f"  definition: >\n")
        f.write(f"    ```{logic_filter_content['definition']}```\n")
    
    print(f"Created logic filter YML file: {logic_filter_file}")


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
            return f"`{macro_name}` #Macro not found in Macros"

    # Replace all macros in the search_query using the regex pattern
    return re.sub(r'`([^`]+)`', replace_macro, search_query)


def organize_detections_by_id(detections, fields, macro_dir, logic_filter_dir):
    organized_detections = {}
    for detection in detections:
        name_snake_case = snake_case(detection['name'])
        detection_id = f"nh-aw_escu_{name_snake_case}"
        organized_detections[detection_id] = {}
        organized_detections[detection_id]['name'] = detection['name']

        for field in fields:
            if field == 'id':  # Skip the 'id' field as we're generating it
                continue
            if field == 'search' and field in detection:
                # Replace macros in the search query and append the specified macros
                search_query = replace_macros_in_search(detection[field], macro_dir, logic_filter_dir)
                search_query = search_query.replace(' | ', '\n    | ')
                search_query += '\n    | `nh-aw_macro_placeholder`\n    | `nh-aw_shadow_package`'
                organized_detections[detection_id][field] = f'>\n    {search_query}'
            elif field in detection:
                organized_detections[detection_id][field] = detection[field]
            elif field in detection.get('tags', {}):
                organized_detections[detection_id][field] = detection['tags'][field]
            else:
                organized_detections[detection_id][field] = None
    return organized_detections

def main():
    # Adjust this path to the actual path where your security_content directory is located
    repo_path = r"<FILE PATH>\security_content"
    
    # Path to the directory containing the macros
    macro_directory = r"<FILE PATH>\security_content\macros"
    
    # Path to the directory where logic filter YML files should be saved
    logic_filter_dir = r"<FILE PATH>\ESCU_Macros"
    
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

    # Pass the macro directory and logic filter directory to the organize_detections_by_id function
    organized_detections = organize_detections_by_id(detections, default_fields, macro_directory, logic_filter_dir)
    
    output_file = mitre_id + "_matched_escu_detections.yml"
    save_detections_to_yaml(organized_detections, output_file)

    print("\nAll matched detections processed and saved successfully.")


if __name__ == "__main__":
    main()