import os
import json
import yaml
import time
import subprocess
from datetime import datetime, timedelta, timezone

# __________                 _________                                               .__                   _____            .___.__  __
# \______   \__ __  ____    /   _____/__ ________ _____________   ____   ______ _____|__| ____   ____     /  _  \  __ __  __| _/|__|/  |_
# |       _/  |  \/    \   \_____  \|  |  \____ \\____ \_  __ \_/ __ \ /  ___//  ___/  |/  _ \ /    \   /  /_\  \|  |  \/ __ | |  \   __\
# |    |   \  |  /   |  \  /        \  |  /  |_> >  |_> >  | \/\  ___/ \___ \ \___ \|  (  <_> )   |  \ /    |    \  |  / /_/ | |  ||  |
# |____|_  /____/|___|  / /_______  /____/|   __/|   __/|__|    \___  >____  >____  >__|\____/|___|  / \____|__  /____/\____ | |__||__|
#        \/           \/          \/      |__|   |__|               \/     \/     \/               \/          \/           \/
#

# Author: Luke Wescott

CONTENT_LIVE_DIR = os.path.expanduser("/workspaces/content-live/client")
SUPPRESSION_JSON_DIR = os.path.expanduser("/workspaces/run-query-cli/")


def read_json(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def read_yaml(file_path):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)


# Function to compare JSON suppression with YAML, skipping duplicates
def compare_suppressions(json_suppression, yaml_suppressions, processed_suppressions):
    json_name = json_suppression["name"]
    json_spl = json_suppression["suppression_string"]
    json_user = json_suppression["user"]
    # Skip if this suppression_string was already processed
    if json_spl in processed_suppressions:
        print(f"Skipping duplicate suppression: {json_name}")
        return False
    processed_suppressions.add(json_spl)  # Mark this suppression_string as processed
    for suppression_id, suppression_data in yaml_suppressions.items():
        if suppression_id == json_name:
            if suppression_data["properties"]["search"] == json_spl:
                print(
                    f"The SPL of these files are the same for {json_name}, or incorrectly pulled from Splunk. Please validate."
                )
            else:
                print(
                    f"The current SPL should show: {suppression_data['properties']['search']}"
                )
                print(f"The SPL in the environment shows: {json_spl}")
            return True
    print(
        f"The SPL from the environment change needs to be added to the suppression file for {json_name}."
    )
    return False


def calculate_expiration_time(splunk_time):
    timestamp = datetime.fromtimestamp(splunk_time, tz=timezone.utc)
    expiration_time = timestamp + timedelta(weeks=1)
    return int(expiration_time.timestamp())


def update_yaml(yaml_path, json_suppression, expiration_time):
    expiration_str = f"_time<{expiration_time}'"
    search_with_expiration = (
        json_suppression["suppression_string"].rstrip("'") + expiration_str
    )
    with open(yaml_path, "a") as file:
        file.write("\n\n")
        file.write(f"  - id: {json_suppression['name']}\n")
        file.write("    properties:\n")
        file.write("      owner: nobody\n")
        file.write(f"      #Original Owner was: {json_suppression['user']}\n")
        file.write(
            f'      description: "Please enter a description. This suppression was originally created in Environment and needs to be redefined in BB"\n'
        )
        file.write(f"      search: {search_with_expiration}\n")


def run_git_command(command, delay=3):
    print(f"Running: {command}")
    subprocess.run(command, shell=True)
    time.sleep(delay)


def main():
    suppression_json_path = os.path.join(
        SUPPRESSION_JSON_DIR, "suppression_audit_group4.json"
    )
    json_data = read_json(suppression_json_path)
    processed_suppressions = set()
    for client_name, client_data in json_data.items():
        if "results" in client_data and client_data["results"]:
            print(f"Processing client: {client_name}")
            yaml_path = os.path.join(CONTENT_LIVE_DIR, client_name, "suppressions.yml")
            yaml_data = read_yaml(yaml_path)
            for json_suppression in client_data["results"]:
                splunk_time = int(
                    datetime.strptime(
                        json_suppression["_time"], "%Y-%m-%dT%H:%M:%S.%f+00:00"
                    ).timestamp()
                )
                expiration_time = calculate_expiration_time(splunk_time)
                if not compare_suppressions(
                    json_suppression, yaml_data, processed_suppressions
                ):
                    update_yaml(yaml_path, json_suppression, expiration_time)
                    user_input = input(
                        f"I see changes made to {client_name}. Do you want me to make a branch with proposed changes? (y/n): "
                    )
                    if user_input.lower() == "y":
                        os.chdir(os.path.join(CONTENT_LIVE_DIR, client_name))
                        print("Checking out main...\n")
                        run_git_command("git checkout main")
                        print("\nChecked out main...\nPulling content...")
                        run_git_command("git pull", delay=10)
                        print("\nPulled main...\nMaking new branch...")
                        branch_name = f"{client_name.lower()}_{json_suppression['name'].replace(' ', '_').lower()}"
                        run_git_command(f"git checkout -b {branch_name}")
                        print("\nChecked out branch\n")
                        print(
                            f"To review the changes, run: 'git checkout {branch_name}' in content-live."
                        )
                    break


if __name__ == "__main__":
    main()

'''
{
    "microsoft": {
        "fields": [],
        "results": [
            {
                "_time": "2024-08-22T08:33:13.423+00:00",
                "action": "modified",
                "app": "SA-ThreatIntelligence",
                "name": "notable_suppression_tempfix",
                "suppression_string": "'`get_notable_index` source=nh-aw_testing_alert IN (40*, 30*, 0*) url=\"*nice-domain.it\" _time<1724385600'",
                "user": "user@microsoft.com"
            }
        ]
    },
    "apple": {
        "fields": [],
        "results": []

}
'''