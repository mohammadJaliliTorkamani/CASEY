import json
from collections import defaultdict, Counter


# Function to get file extension
def get_file_extension(file_name):
    return file_name.split('.')[-1]


# Function to analyze buggy code data
def analyze_buggy_code(data):
    file_count = defaultdict(int)
    language_count = defaultdict(int)
    deletion_count = defaultdict(int)
    line_deletion_count = Counter()
    total_files = 0
    total_deletions = 0

    for element in data:
        for buggy in element['buggy_code']:
            file = buggy['file']
            total_files += 1
            file_extension = get_file_extension(file)
            file_count[file] += 1
            language_count[file_extension] += 1

            num_deletions = len(buggy['deletions'])
            deletion_count[file] += num_deletions
            total_deletions += num_deletions

            for deletion in buggy['deletions']:
                line_deletion_count[deletion['line_content']] += 1

    # Calculate percentages
    language_percentage = {lang: (count / total_files) * 100 for lang, count in language_count.items()}
    file_percentage = {file: (count / total_files) * 100 for file, count in file_count.items()}
    average_deletions = total_deletions / total_files if total_files else 0

    # Sort results
    sorted_language_percentage = dict(sorted(language_percentage.items(), key=lambda item: item[1], reverse=True))
    sorted_file_percentage = dict(sorted(file_percentage.items(), key=lambda item: item[1], reverse=True))
    sorted_deletion_count = dict(sorted(deletion_count.items(), key=lambda item: item[1], reverse=True))

    return {
        "language_percentage": sorted_language_percentage,
        "file_percentage": sorted_file_percentage,
        "deletion_count": sorted_deletion_count,
        "line_deletion_count": line_deletion_count,
        "average_deletions": average_deletions
    }


# Function to read JSON data from a file
def read_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


# Main function to execute the analysis
def main(file_path):
    data = read_json_file(file_path)
    analysis_results = analyze_buggy_code(data)

    # Display the results
    print("Language Percentage:")
    for lang, percent in analysis_results['language_percentage'].items():
        print(f"{lang}: {percent:.2f}%")

    print("\nFile Percentage:")
    for file, percent in analysis_results['file_percentage'].items():
        print(f"{file}: {percent:.2f}%")

    print("\nDeletion Count per File:")
    for file, count in analysis_results['deletion_count'].items():
        print(f"{file}: {count} deletions")

    print("\nMost Frequently Deleted Lines:")
    for line, count in analysis_results['line_deletion_count'].most_common(5):
        print(f"'{line}': {count} times")

    print(f"\nAverage Number of Deletions per Buggy Code: {analysis_results['average_deletions']:.2f}")


if __name__ == "__main__":
    # Specify the path to your JSON file
    json_file_path = 'cleaned_code_entries.json'
    main(json_file_path)
