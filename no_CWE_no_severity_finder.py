import json

# Load the JSON data from files
with open('./data/cve_training.json', 'r') as file1:
    first_data = json.load(file1)

with open('./data/cve_to_cwe_2016_2024.json', 'r') as file2:
    second_data = json.load(file2)

# Find CVEs with no score or no severity, ensuring they exist in both JSONs
invalid_cves = []
for item in first_data:
    cve = item.get("CVE")
    if item.get("description") != "No descriptions found.":
        matching_entry = next((entry for entry in second_data if entry.get("CVE") == cve), None)

        if matching_entry:
            score = matching_entry.get("score")
            severity = matching_entry.get("severity")

            if score == "" or not severity:
                print(f"Adding {cve}...")
                invalid_cves.append(cve)

# Output the invalid CVEs
print(f"There are {len(invalid_cves)} invalid cves out of {len(first_data)}")
print("CVEs with no score or no severity:")
for cve in invalid_cves:
    print(cve)

# Optional: Save results to a file
# with open('invalid_cves.json', 'w') as outfile:
#     json.dump(invalid_cves, outfile, indent=4)
