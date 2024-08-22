def extract_ids_from_file(file_path):
    """
    Manually extracts all `id` values from the provided YAML file.
    """
    ids = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("- id:"):
                # Extract the id value after "- id: "
                id_value = line.split(":", 1)[1].strip()
                ids.append(id_value)
    
    return ids

def generate_splunk_search(ids):
    """
    Generates a Splunk search query using `source IN` based on the provided ids.
    """
    # Join all ids into a comma-separated list
    id_list = ", ".join([f'"{id_name}"' for id_name in ids])
    # Create the search query
    search_query = f"`notable_index` source IN ({id_list}) | table urgency_would_be, count"

    return search_query

def write_to_file(output_file, search_query):
    """
    Writes the generated search query to the output YAML file.
    """
    with open(output_file, 'w') as file:
        file.write(f"- search: >\n    {search_query}\n")

def main():
    # Ask the user to enter the YAML file name
    input_file = input("Enter the name of the YAML file: ")

    # Extract IDs from the input file
    ids = extract_ids_from_file(input_file)

    # Generate the Splunk search query
    splunk_search_query = generate_splunk_search(ids)

    # Write the search query to the new baseline_ttp.yml file
    output_file = "baseline_ttp.yml"
    write_to_file(output_file, splunk_search_query)

    print(f"Search query generated and written to {output_file}")

if __name__ == "__main__":
    main()
