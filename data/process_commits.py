import json
import os
import time

from description_extraction import extract_issue_description_from_commit


def process_commit_urls(json_input_file, json_output_file):
    start_time = time.time()

    # 检查输出文件是否存在，不存在则创建一个空的
    if not os.path.exists(json_output_file):
        with open(json_output_file, 'w') as f:
            json.dump([], f)

    # 读取输入文件中的URL
    with open(json_input_file, 'r') as f:
        data = json.load(f)

    total_urls = len(data)
    success_count = 0
    no_commit_message_count = 0
    failed_retrieve_count = 0
    null_description_count = 0

    # 读取已经存在的输出文件
    with open(json_output_file, 'r') as f:
        existing_data = json.load(f)

    processed_urls = {item["url"] for item in existing_data}

    # 处理每个URL
    for index, item in enumerate(data):
        url = item.get("url")
        print(f"Processing URL {index + 1}/{total_urls}: {url}")
        output_item = {"url": url}

        if url and url not in processed_urls:
            descriptions = extract_issue_description_from_commit(url)
            if descriptions:
                success_count += 1
                for pr_number, description in descriptions.items():
                    output_item["github description"] = description
            else:
                null_description_count += 1
                output_item["github description"] = "No descriptions found."
                print(f"No descriptions found for URL: {url}")
        else:
            failed_retrieve_count += 1
            output_item["github description"] = "Failed to retrieve URL."
            print(f"Failed to retrieve URL: {url}")

        existing_data.append(output_item)
        with open(json_output_file, 'w') as f:
            json.dump(existing_data, f, indent=4)

    end_time = time.time()
    total_time = end_time - start_time

    print(f"Total URLs: {total_urls}")
    print(f"Successfully extracted descriptions: {success_count}")
    print(f"No commit message found: {no_commit_message_count}")
    print(f"Failed to retrieve: {failed_retrieve_count}")
    print(f"Null descriptions: {null_description_count}")
    print(f"Total time taken: {total_time:.2f} seconds")


if __name__ == "__main__":
    input_file = 'cve_training.json'
    output_file = 'github_description.json'
    process_commit_urls(input_file, output_file)
