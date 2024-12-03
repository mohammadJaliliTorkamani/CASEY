import json
import os
import pandas as pd


def create_excel_from_json(json_file_paths_normal, json_file_paths_finetuned, output_excel_path):
    # Initialize lists to hold the data for the Excel file
    data_normal = []
    data_finetuned = []

    # Function to extract data from JSON and format it as a row
    def extract_row(json_file_path):
        with open(json_file_path, 'r') as file:
            json_data = json.load(file)

        filtered_data = {key: value for key, value in json_data.items() if key not in ['evaluations', 'metrics','TOTAL_NUMBER_OF_SAMPLES_counter','timestamp']}
        row = {'File Name': os.path.basename(json_file_path)}
        row.update(filtered_data)
        return row

    # Process normal files
    for json_file_path in json_file_paths_normal:
        data_normal.append(extract_row(json_file_path))

    # Process fine-tuned files
    for json_file_path in json_file_paths_finetuned:
        data_finetuned.append(extract_row(json_file_path))

    # Combine the data: normal files first, then fine-tuned files
    data_combined = data_normal + data_finetuned

    # Create a DataFrame from the combined data
    df = pd.DataFrame(data_combined)

    # Write the DataFrame to an Excel file
    df.to_excel(output_excel_path, index=False)


# Example usage
json_file_paths_normal = ['/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_gpt-3.5-turbo_gpt-3.5-turbo.json',
                          '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_files_gpt-3.5-turbo_gpt-3.5-turbo.json',
                          '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_method_gpt-3.5-turbo_gpt-3.5-turbo.json',
                          '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_hunks_gpt-3.5-turbo_gpt-3.5-turbo.json',
                          ]

json_file_paths_finetuned = ['/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_severity_fine_tuned_cwe_fine_tuned.json',
                             '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_files_severity_fine_tuned_cwe_fine_tuned.json',
                             '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_method_severity_fine_tuned_cwe_fine_tuned.json',
                             '/Users/mjalilitorkamani2/Codes/BugType_Categorization/evaluated_final_analysis_of_bug_description_and_hunks_severity_fine_tuned_cwe_fine_tuned.json',
                            ]
output_excel_path = 'final samples - final/output.xlsx'
create_excel_from_json(json_file_paths_normal, json_file_paths_finetuned, output_excel_path)
