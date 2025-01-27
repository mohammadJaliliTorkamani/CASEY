import json
import random
import requests
from urllib.parse import urlparse


def select_random_records(json_file_path, additional_file_path, num_records):
    try:
        # Load the main JSON file
        with open(json_file_path, 'r') as file:
            data = json.load(file)

        # Check if "evaluations" field exists and is a list
        if not isinstance(data.get("evaluations"), list):
            raise ValueError("The 'evaluations' field is not present or is not a list.")

        evaluations = data["evaluations"]

        # Select 'num_records' random records from the evaluations array
        if len(evaluations) < num_records:
            raise ValueError(f"The evaluations array has fewer than {num_records} records.")

        random_records = random.sample(evaluations, num_records)

        # Load the additional file for extracting the "url" field
        with open(additional_file_path, 'r') as additional_file:
            additional_data = json.load(additional_file)

        # Print the "reference_id", "cwe_equality_status", "severity_label_equality_status", and extensions of edited files
        print("Selected records:")
        for record in random_records:
            reference_id = record.get("reference_id", "N/A")
            cwe_status = record.get("cwe_equality_status", "N/A")
            severity_status = record.get("severity_label_equality_status", "N/A")

            # Find the corresponding "url" in the additional data
            url = next((item.get("url", "N/A") for item in additional_data if item.get("id") == reference_id),
                       "N/A")

            file_extensions = set()
            if url != "N/A" and "github.com" in url:
                try:
                    # Extract commit details from GitHub API
                    parsed_url = urlparse(url)
                    path_parts = parsed_url.path.strip("/").split("/")
                    if len(path_parts) >= 4 and path_parts[2] == "commit":
                        owner, repo, commit_sha = path_parts[0], path_parts[1], path_parts[3]
                        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"

                        response = requests.get(api_url)
                        if response.status_code == 200:
                            commit_data = response.json()
                            for file in commit_data.get("files", []):
                                filename = file.get("filename", "")
                                if "." in filename:
                                    file_extensions.add(filename.split(".")[-1])
                        else:
                            print(f"Failed to fetch commit details for URL: {url}")
                except Exception as e:
                    print(f"Error processing GitHub URL {url}: {e}")

            print(
                f"reference_id: {reference_id}, cwe_equality_status: {cwe_status}, severity_label_equality_status: {severity_status}, url: {url}, file_extensions: {file_extensions}")

    except FileNotFoundError as e:
        print(f"File not found: {e.filename}")
    except json.JSONDecodeError:
        print("Error decoding JSON. Please check the file format.")
    except ValueError as e:
        print("ValueError:", e)


# Example usage
# Replace 'path_to_your_json_file.json' and 'path_to_additional_file.json' with the paths to your JSON files
json_file_path = 'experiments/final/evaluated_final_analysis_of_bug_description_and_hunks_severity_fine_tuned_cwe_fine_tuned.json'
additional_file_path = 'experiments/final/final_analysis_of_bug_description_and_hunks_severity_fine_tuned_cwe_fine_tuned.json'
num_records = 50
select_random_records(json_file_path, additional_file_path, num_records)
