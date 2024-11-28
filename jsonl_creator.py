import json
import random

import constants
import llm
import utils
from extractor import Extractor

llm = llm.LLM((constants.LLM_NORMAL_MODEL,constants.LLM_NORMAL_MODEL))


def meets_buggy_code_details(data_obj, CVE2CWE_OBJ) -> tuple:
    total_number_of_tokens = 0
    new_buggy_codes = list()
    failure_reason = None
    GT_CWEs = utils.get_CWEs_of_CVE(data_obj['CVE'], CVE2CWE_OBJ)
    GT_severities = utils.get_severities_of_CVE(data_obj['CVE'], CVE2CWE_OBJ)
    if len(GT_CWEs) == 1 and GT_CWEs[0] == "Unknown-CWE":
        failure_reason = "EMPTY_OR_UNKNOWN_GT_CWEs"
    elif len(GT_severities) == 0:
        failure_reason = "EMPTY_SEVERITIES"
    elif len(data_obj['buggy_code']) == 0:
        failure_reason = "EMPTY_BUGGY_CODE"
    else:
        for item in data_obj['buggy_code']:
            if 'deletions' not in item or len(item['deletions']) == 0:
                failure_reason = "EMPTY_HUNKS"
            elif ('file' not in item or (
                    item['file'].split('.')[-1] not in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS)):
                failure_reason = "NON_ACCEPTABLE_FILE"
            else:
                total_number_of_tokens += utils.count_gpt_tokens(item['file_content'])
                if total_number_of_tokens < constants.MAX_TOKEN_NUMBER:
                    new_buggy_codes.append(item)
                else:
                    return None, f"FILES_TOKENS_EXCEEDED ({total_number_of_tokens})"

        if len(new_buggy_codes) > 0:
            data_obj['buggy_code'] = new_buggy_codes
            return data_obj, None

    return None, failure_reason


def filter_methods(extracted_methods, deletions, temp_file_path: str):
    try:
        filtered_methods = list()
        if deletions and len(deletions) > 0:
            for method in extracted_methods:
                method_range = utils.extract_line_range(method, temp_file_path)
                if method_range != (None, None):
                    for item in deletions:
                        if (len(str(item['line_content']).strip()) > 0 and
                                method_range[0] <= int(item['line_number']) + 1 <= method_range[1]):
                            filtered_methods.append(method)

            return filtered_methods

        return extracted_methods
    finally:
        utils.remove_file(temp_file_path)


def write_jsonl(data, train_ratio, train_file_path, test_file_path):
    data_train = data[:int(len(data) * train_ratio)]
    print(f"Writing data to {train_file_path} with size {len(data_train)}...")
    with open(train_file_path, 'w') as f:
        for entry in data_train:
            f.write(json.dumps(entry) + '\n')
    print(f"Data successfully written to {train_file_path}.")

    data_test = data[int(len(data) * train_ratio):]
    print(f"Writing data to {test_file_path} with size {len(data_test)}...")
    with open(test_file_path, 'w') as f:
        for entry in data_test:
            f.write(json.dumps(entry) + '\n')
    print(f"Data successfully written to {test_file_path}.")


def create_jsonl_object(user_severity, system_severity, user_cwe, system_cwe, gt_SEVERITIES, gt_CWEs, results,
                        fine_tuning_for_CWE):
    if user_severity is None or system_severity is None or user_cwe is None or system_cwe is None or gt_SEVERITIES is None or gt_CWEs is None or len(
            gt_CWEs) == 0 or len(gt_SEVERITIES) == 0:
        return

    if fine_tuning_for_CWE:
        output = ('{\n'
                  '"EXACT_CWE_IDS": [' + ', '.join(("'" + str(cwe) + "'") for cwe in gt_CWEs) + '],\n' +
                  '"TOP_FIVE_CWE_IDS": [' + ', '.join(("'" + str(cwe) + "'") for cwe in gt_CWEs) + ']\n' +
                  '}')

        messages = [
            {"role": "system", "content": system_cwe},
            {"role": "user", "content": user_cwe},
            {"role": "assistant", "content": output}
        ]

        output_entry = {"messages": messages}

        results.append(output_entry)
    else:
        output = ('{\n'
                  '"SEVERITY_LABEL": "' + str(gt_SEVERITIES[0]) + '",\n' +
                  '"SEVERITY_SCORE": ' + str(gt_SEVERITIES[1]) + '\n' +
                  '}')

        messages = [
            {"role": "system", "content": system_severity},
            {"role": "user", "content": user_severity},
            {"role": "assistant", "content": output}
        ]

        output_entry = {"messages": messages}
        results.append(output_entry)


def extract_jsonl_records(data_array, CVE2CWE_OBJ, fine_tuning_for_CWE: bool = False):
    results = []

    for idx, data_obj in enumerate(data_array):
        if idx % 100 == 0:
            print(("%.1f percents Completed") % ((idx + 1) / len(data_array) * 100))
        if utils.date_is_after(data_obj['date'], constants.LLM_MODEL_CUT_OFF_DATE):
            filtered_data_object = meets_buggy_code_details(data_obj, CVE2CWE_OBJ)
            if filtered_data_object[1] is None:
                if filtered_data_object[0] is None:
                    exit(0)
                else:
                    gt_CVE = data_obj['CVE']
                    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
                    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
                    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
                    cvss_version = gt_CVSS_versions[0] if len(
                        gt_CVSS_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS

                    hunks = {}
                    for buggy_code_obj in data_obj['buggy_code']:
                        hunks_temp = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                               buggy_code_obj['deletions']).extract_hunks()
                        if len(hunks_temp) > 0:
                            hunks[buggy_code_obj['file']] = hunks_temp

                    methods = {}
                    for buggy_code_obj in data_obj['buggy_code']:
                        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'],
                                                                      buggy_code_obj['file_content'],
                                                                      buggy_code_obj['deletions']).extract_methods()
                        if extracted_methods is not None:
                            methods[buggy_code_obj['file']] = filter_methods(extracted_methods,
                                                                             buggy_code_obj['deletions'],
                                                                             temp_file_path)

                    buggy_code = data_obj['buggy_code']
                    description = data_obj['description']

                    description_experiment_llm_fields_for_severity_inference = llm.inference_with_description(
                        description, gt_CVSS_versions, True)
                    files_experiment_llm_fields_for_severity_inference = llm.inference_with_buggy_files(buggy_code,
                                                                                                        gt_CVSS_versions,
                                                                                                        True)
                    methods_experiment_llm_fields_for_severity_inference = llm.inference_with_buggy_methods(methods,
                                                                                                            gt_CVSS_versions,
                                                                                                            True)
                    hunks_experiment_llm_fields_for_severity_inference = llm.inference_with_buggy_hunks(hunks,
                                                                                                        gt_CVSS_versions,
                                                                                                        True)
                    description_plus_files_experiment_llm_fields_for_severity_inference = llm.inference_with_description_and_files(
                        description, buggy_code, gt_CVSS_versions, True)
                    description_plus_methods_experiment_llm_fields_for_severity_inference = llm.inference_with_description_and_methods(
                        description, methods, gt_CVSS_versions, True)
                    description_plus_hunks_experiment_llm_fields_for_severity_inference = llm.inference_with_description_and_hunks(
                        description, hunks, gt_CVSS_versions, True)

                    u1_desc, s1_desc, u2_desc, s2_desc = description_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_desc, s1_desc, u2_desc, s2_desc, gt_SEVERITIES[cvss_version], gt_CWEs,
                                        results, fine_tuning_for_CWE)
                    u1_files, s1_files, u2_files, s2_files = files_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_files, s1_files, u2_files, s2_files, gt_SEVERITIES[cvss_version], gt_CWEs,
                                        results, fine_tuning_for_CWE)
                    u1_methods, s1_methods, u2_methods, s2_methods = methods_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_methods, s1_methods, u2_methods, s2_methods, gt_SEVERITIES[cvss_version],
                                        gt_CWEs, results, fine_tuning_for_CWE)
                    u1_hunks, s1_hunks, u2_hunks, s2_hunks = hunks_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_hunks, s1_hunks, u2_hunks, s2_hunks, gt_SEVERITIES[cvss_version], gt_CWEs,
                                        results, fine_tuning_for_CWE)
                    u1_desc_files, s1_desc_files, u2_desc_files, s2_desc_files = description_plus_files_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_desc_files, s1_desc_files, u2_desc_files, s2_desc_files,
                                        gt_SEVERITIES[cvss_version], gt_CWEs, results, fine_tuning_for_CWE)
                    u1_desc_methods, s1_desc_methods, u2_desc_methods, s2_desc_methods = description_plus_methods_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_desc_methods, s1_desc_methods, u2_desc_methods, s2_desc_methods,
                                        gt_SEVERITIES[cvss_version], gt_CWEs, results, fine_tuning_for_CWE)
                    u1_desc_hunks, s1_desc_hunks, u2_desc_hunks, s2_desc_hunks = description_plus_hunks_experiment_llm_fields_for_severity_inference
                    create_jsonl_object(u1_desc_hunks, s1_desc_hunks, u2_desc_hunks, s2_desc_hunks,
                                        gt_SEVERITIES[cvss_version], gt_CWEs, results, fine_tuning_for_CWE)

            else:
                # print("The record does not meet criteria. reason:", filtered_data_object[1])
                pass
        else:
            # print("The code is before cut-off date")
            pass
    return results


def find_dictionary_value_in_list_with_key(key: str, _list: list) -> str | None:
    for item in _list:
        if item.get('role') == key:
            return item.get('content')
    return None


def filter_based_on_window_size(jsonl_records):
    print("Filtering based on window size: ", constants.MAX_TOKEN_NUMBER, "Input list size:", len(jsonl_records))
    results = []
    for record in jsonl_records:
        if utils.count_gpt_tokens(
                find_dictionary_value_in_list_with_key('user',
                                                       record['messages']) + find_dictionary_value_in_list_with_key(
                    'assistant', record['messages']) + find_dictionary_value_in_list_with_key('system', record[
                    'messages'])) < constants.MAX_TOKEN_NUMBER:
            results.append(record)
    print("Filtered successfully", constants.MAX_TOKEN_NUMBER, "New input list size:", len(jsonl_records))
    return results


def main():
    DATA_ARRAY = utils.load_json_file(constants.FINE_TUNING_JSON_DATASET_PATH)
    print("Initial dataset size:", len(DATA_ARRAY))
    random.shuffle(DATA_ARRAY)
    CVE2CWE_OBJ = utils.load_json_file(constants.CVE2CWE_PATH)
    jsonl_records_severity = extract_jsonl_records(DATA_ARRAY, CVE2CWE_OBJ, False)
    jsonl_records_severity = filter_based_on_window_size(jsonl_records_severity)
    write_jsonl(jsonl_records_severity, constants.FINE_TUNING_TRAIN_SPLIT_RATIO,
                constants.FINE_TUNING_JSONL_DATASET_TRAIN_PATH_SEVERITY,
                constants.FINE_TUNING_JSONL_DATASET_TEST_PATH_SEVERITY)
    jsonl_records_cwe = extract_jsonl_records(DATA_ARRAY, CVE2CWE_OBJ, True)
    jsonl_records_cwe = filter_based_on_window_size(jsonl_records_cwe)
    write_jsonl(jsonl_records_cwe, constants.FINE_TUNING_TRAIN_SPLIT_RATIO,
                constants.FINE_TUNING_JSONL_DATASET_TRAIN_PATH_CWE, constants.FINE_TUNING_JSONL_DATASET_TEST_PATH_CWE)


if __name__ == '__main__':
    main()
