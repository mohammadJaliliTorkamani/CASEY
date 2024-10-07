import json
import os
import re
from datetime import datetime

import tiktoken

import constants


def load_json_file(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data


def print_nested(output: str, nest_degree: int = 0):
    if nest_degree < 0:
        nest_degree = 0
    print("\t" * nest_degree, output)


def remove_file(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except Exception as e:
        return False


def count_gpt_tokens(text: str) -> int:
    tokenizer = tiktoken.encoding_for_model(constants.LLM_MODEL)
    tokens = tokenizer.encode(text)
    return len(tokens)

def extract_line_range(search_string: str, file_path: str)-> tuple:
    occurrences = []

    # Read the entire file content
    with open(file_path, 'r') as file:
        file_content = file.read()

    # Create a regex pattern for multi-line matching
    pattern = re.compile(re.escape(search_string), re.MULTILINE | re.DOTALL)

    for match in pattern.finditer(file_content):
        start_pos = match.start()
        end_pos = match.end()

        # Calculate line numbers
        start_line = file_content.count('\n', 0, start_pos) + 1
        end_line = file_content.count('\n', 0, end_pos) + 1

        occurrences.append((start_line, end_line))

    return occurrences[0] if len(occurrences) > 0 else (None,None)
def save_json(address, content):
    # Ensure the directory exists; if not, create it
    directory = os.path.dirname(address)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Write the JSON content to the file
    with open(address, 'w', encoding='utf-8') as file:
        json.dump(content, file, ensure_ascii=False, indent=4)


def is_not_in_list(str_corpus: list, key: str) -> bool:
    return all(key != item for item in str_corpus)


def date_is_after(date_str1: str, date_str2: str) -> bool:
    date1 = datetime.strptime(date_str1, "%Y-%m-%d")
    date2 = datetime.strptime(date_str2, "%Y-%m-%d")
    return date1 > date2


"""
We assume it is true even if one CWE of the candidate CVE is among top CWEs
"""


def get_CWEs_of_CVE(candidate_CVE):
    _list = list()
    for obj in load_json_file(constants.CVE2CWE_PATH):
        if obj['CVE'] == candidate_CVE:
            for CWE in obj['CWE']:
                _list.append(CWE['id'])
    return _list


def extract_json_from_string(input_string):
    try:
        # Regular expression to find JSON objects, supporting newlines
        json_pattern = re.compile(r'({.*?})', re.DOTALL)
        match = json_pattern.search(input_string)

        if match:
            json_obj = match.group(1)
            return json_obj
        else:
            return None
    except json.JSONDecodeError:
        return None


def is_among_top_CWEs(candidate_CWEs: list, top_CWEs):
    for candidate_CWE in candidate_CWEs:
        if candidate_CWE in [item['id'] for item in top_CWEs]:
            return True

    return False


def get_severities_of_CVE(candidate_CVE) -> dict:
    _list = dict()
    for obj in load_json_file(constants.CVE2CWE_PATH):
        if obj['CVE'] == candidate_CVE:
            for severity in obj['severity']:
                if 'baseMetricV3' in severity and 'cvssV3' in severity['baseMetricV3'] and 'baseSeverity' in \
                        severity['baseMetricV3']['cvssV3']:
                    version = severity['baseMetricV3']['cvssV3']['version']
                    _list['V' + str(version)] = severity['baseMetricV3']['cvssV3']['baseSeverity']
                elif 'baseMetricV2' in severity and 'cvssV2' in severity['baseMetricV2'] and 'baseSeverity' in \
                        severity['baseMetricV2']['cvssV2']:
                    version = severity['baseMetricV2']['cvssV2']['version']
                    _list['V' + str(version)] = severity['baseMetricV2']['cvssV2']['baseSeverity']

    return _list


def extract_cvss_versions(candidate_CVE) -> list:
    _list = list()
    for obj in load_json_file(constants.CVE2CWE_PATH):
        if obj['CVE'] == candidate_CVE:
            for severity in obj['severity']:
                if 'baseMetricV3' in severity and 'cvssV3' in severity['baseMetricV3'] and 'baseSeverity' in \
                        severity['baseMetricV3']['cvssV3']:
                    version = severity['baseMetricV3']['cvssV3']['version']
                    _list.append('V' + str(version))
                elif 'baseMetricV2' in severity and 'cvssV2' in severity['baseMetricV2'] and 'baseSeverity' in \
                        severity['baseMetricV2']['cvssV2']:
                    version = severity['baseMetricV2']['cvssV2']['version']
                    _list.append('V' + str(version))

    return _list


def save_file(file_name, file_content):
    with open(file_name, 'w', encoding='utf-8') as file:
        file.write(file_content)
