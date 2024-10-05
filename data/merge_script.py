import json
import sys


def add_github_description(source_path, dest_path):
    # 读取源JSON文件
    with open(source_path, 'r', encoding='utf-8') as source_file:
        source_data = json.load(source_file)

    # 读取目标JSON文件
    with open(dest_path, 'r', encoding='utf-8') as dest_file:
        dest_data = json.load(dest_file)

    # 创建一个字典来存储source数据中的url和对应的github_description
    source_dict = {item['url']: item['github_description'] for item in source_data if
                   'url' in item and 'github_description' in item}

    # 遍历目标数据，匹配url并添加github_description
    for item in dest_data:
        if 'url' in item and item['url'] in source_dict:
            item['github_description'] = source_dict[item['url']]

    # 将更新后的目标数据写回文件
    with open(dest_path, 'w', encoding='utf-8') as dest_file:
        json.dump(dest_data, dest_file, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <source_json_path> <dest_json_path>")
        sys.exit(1)

    source_json_path = sys.argv[1]
    dest_json_path = sys.argv[2]

    add_github_description(source_json_path, dest_json_path)
