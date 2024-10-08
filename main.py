# WHY NOT ALL FILES ARE ADDED IJTO THE USER FILE?
import json
import random

import constants
import utils
from constants import LLM_MODEL
from evaluator import Evaluator
from extractor import Extractor
from llm import LLM

llm = LLM(LLM_MODEL)
evaluator = Evaluator()


def save_to_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)


def run_experiment_buggy_files(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    llm_input, llm_output = llm.inference_with_buggy_files(data_obj['buggy_code'], gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_buggy_methods(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    methods = {}
    for buggy_code_obj in data_obj['buggy_code']:
        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                      buggy_code_obj['deletions']).extract_methods()
        if extracted_methods is not None:
            methods[buggy_code_obj['file']] = filter_methods(extracted_methods, buggy_code_obj['deletions'],
                                                             temp_file_path)
        utils.remove_file(temp_file_path)
    llm_input, llm_output = llm.inference_with_buggy_methods(methods, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_buggy_hunks(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks_temp = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                               buggy_code_obj['deletions']).extract_hunks()
        if len(hunks_temp) > 0:
            hunks[buggy_code_obj['file']] = hunks_temp

    llm_input, llm_output = llm.inference_with_buggy_hunks(hunks, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description(data_obj, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    description = data_obj['description'] \
        if (data_obj['github_description'] == "No descriptions found." or data_obj['github_description'] is None or len(
        data_obj['github_description'].strip()) == 0) \
        else data_obj['github_description']
    llm_input, llm_output = llm.inference_with_description(description, gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description_and_files(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    description = data_obj['description'] \
        if (data_obj['github_description'] == "No descriptions found." or data_obj['github_description'] is None or len(
        data_obj['github_description'].strip()) == 0) \
        else data_obj['github_description']
    llm_input, llm_output = llm.inference_with_description_and_files(description, data_obj['buggy_code'],
                                                                     gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def extract_first_or_second_values(lst: list, extract_first: bool):
    return [x[0 if extract_first_or_second_values else 1] for x in lst]


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


def run_experiment_bug_description_and_methods(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    methods = {}
    for buggy_code_obj in data_obj['buggy_code']:
        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                      buggy_code_obj['deletions']).extract_methods()
        if extracted_methods is not None:
            methods[buggy_code_obj['file']] = filter_methods(extracted_methods, buggy_code_obj['deletions'],
                                                             temp_file_path)

    llm_input, llm_output = None, None
    if len(methods) > 0:
        description = data_obj['description'] \
            if (data_obj['github_description'] == "No descriptions found." or data_obj[
            'github_description'] is None or len(data_obj['github_description'].strip()) == 0) \
            else data_obj['github_description']
        llm_input, llm_output = llm.inference_with_description_and_methods(description, methods,
                                                                           gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description_and_hunks(data_obj: dict, CVE2CWE_OBJ):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks_temp = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                               buggy_code_obj['deletions']).extract_hunks()
        if len(hunks_temp) > 0:
            hunks[buggy_code_obj['file']] = hunks_temp

    description = data_obj['description'] \
        if (data_obj['github_description'] == "No descriptions found." or data_obj['github_description'] is None or len(
        data_obj['github_description'].strip()) == 0) \
        else data_obj['github_description']
    llm_input, llm_output = llm.inference_with_description_and_hunks(description, hunks, gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'], data_obj['date'], data_obj['github_description'])


def meets_buggy_code_details(data_obj, CVE2CWE_OBJ) -> tuple:
    total_number_of_tokens = 0
    new_buggy_codes = list()
    failure_reason = None
    GT_CWEs = utils.get_CWEs_of_CVE(data_obj['CVE'], CVE2CWE_OBJ)
    if len(GT_CWEs) == 1 and GT_CWEs[0] == "Unknown-CWE":
        failure_reason = "EMPTY_OR_UNKNOWN_GT_CWEs"
    elif len(data_obj['buggy_code'])==0:
        failure_reason = "EMPTY_BUGGY_CODE"
    else:
        for item in data_obj['buggy_code']:
            if 'deletions' not in item or len(item['deletions']) == 0:
                failure_reason = "EMPTY_HUNKS"
            elif ('file' not in item or (item['file'].split('.')[-1] not in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS)):
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


def run_experiment(data_array, _list, runner, CVE2CWE_OBJ):
    data_array_length = len(data_array) if len(data_array) == -1 else min(len(data_array),
                                                                          constants.MAX_NUMBER_OF_RECORDS_PER_EXPERIMENT)
    not_inferred_cases = list()
    for idx, data_obj in enumerate(data_array):
        print("Record url: ", data_obj['url'], "Experiment Progress: ", 100.0 * (idx + 1) / data_array_length, "%")
        if utils.date_is_after(data_obj['date'], constants.LLM_MODEL_CUT_OFF_DATE):
            filtered_data_object = meets_buggy_code_details(data_obj, CVE2CWE_OBJ)
            if filtered_data_object[1] is None:
                if filtered_data_object[0] is None:
                    exit(0)
                _list.append(runner(filtered_data_object[0], CVE2CWE_OBJ))
            else:
                not_inferred_cases.append({'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                                           'reason': 'The record does not not meet the criteria. ' +
                                                     filtered_data_object[1]})
        else:
            not_inferred_cases.append({'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                                       'reason': 'The record is not new enough.'})
        if idx + 1 == constants.MAX_NUMBER_OF_RECORDS_PER_EXPERIMENT:
            break

    return not_inferred_cases


if __name__ == '__main__':
    data_array = utils.load_json_file(constants.DATA_PATH)
    random.shuffle(data_array)
    evaluations_buggy_files = list()
    evaluations_buggy_methods = list()
    evaluations_buggy_hunks = list()
    evaluations_bug_description = list()
    evaluations_bug_description_and_files = list()
    evaluations_bug_description_and_methods = list()
    evaluations_bug_description_and_hunks = list()
    not_inferred_cases = list()

    CVE2CWE_OBJ = utils.load_json_file(constants.CVE2CWE_PATH)

    variants = [
        # ("final_analysis_of_buggy_files", evaluations_buggy_files, run_experiment_buggy_files),
                ("final_analysis_of_buggy_methods", evaluations_buggy_methods, run_experiment_buggy_methods),
                ("final_analysis_of_buggy_hunk", evaluations_buggy_hunks, run_experiment_buggy_hunks),
                ("final_analysis_of_bug_description", evaluations_bug_description, run_experiment_bug_description),
                ("final_analysis_of_bug_description_and_files", evaluations_bug_description_and_files,
                 run_experiment_bug_description_and_files),
                ("final_analysis_of_bug_description_and_method", evaluations_bug_description_and_methods,
                 run_experiment_bug_description_and_methods),
                ("final_analysis_of_bug_description_and_hunks", evaluations_bug_description_and_hunks,
                 run_experiment_bug_description_and_hunks)]

    for idx, (exp_name, list_to_add, runner) in enumerate(variants):
        print(f"\n---> Experiment: {exp_name} | {idx + 1} of {len(variants)}")
        not_inferred_cases = run_experiment(data_array, list_to_add, runner, CVE2CWE_OBJ)
        final_analysis = Evaluator.analyze_evaluations(list_to_add)
        save_to_json(f'{exp_name}.json', final_analysis)
        print(
            f"\nThe experiment result was successfully saved at {exp_name}.json file | Overall Accuracy: {final_analysis['accuracy_overall']}%")

        if idx == len(variants) - 1:
            save_to_json('not_inferred_cases.json', not_inferred_cases)
