"""
NOTE: By adding other LLM models, the code will slightly change throughout the tool in order to handle token counting mechanism
"""
import random

import constants
import utils
from evaluator import Evaluator
from formatter import Formatter
from extractor import Extractor
from llm import LLM

llm = LLM((constants.LLM_NORMAL_MODEL, constants.LLM_NORMAL_MODEL))
formatter = Formatter()
evaluator = Evaluator()


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


def run_experiment_buggy_files(data_obj: dict, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_buggy_files(data_obj['buggy_code'],
                                                                     gt_CVSS_versions)  # Each element of tuple is as (type, llm_input, llm_output)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_buggy_methods(data_obj: dict, CVE2CWE_OBJ, models, id):
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

    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_buggy_methods(methods, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_buggy_hunks(data_obj: dict, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks_temp = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                               buggy_code_obj['deletions']).extract_hunks()
        if len(hunks_temp) > 0:
            hunks[buggy_code_obj['file']] = hunks_temp

    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_buggy_hunks(hunks, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description(data_obj, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    description = data_obj['description']

    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_description(description, gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description_and_files(data_obj: dict, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    description = data_obj['description']

    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_description_and_files(description, data_obj['buggy_code'],
                                                                               gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description_and_methods(data_obj: dict, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    methods = {}
    for buggy_code_obj in data_obj['buggy_code']:
        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                      buggy_code_obj['deletions']).extract_methods()
        if extracted_methods is not None:
            methods[buggy_code_obj['file']] = filter_methods(extracted_methods, buggy_code_obj['deletions'],
                                                             temp_file_path)

    severity_llm_pack, cwe_llm_pack = None, None
    if len(methods) > 0:
        description = data_obj['description']

        llm.set_models_pair(models)
        severity_llm_pack, cwe_llm_pack = llm.inference_with_description_and_methods(description, methods,
                                                                                     gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


def run_experiment_bug_description_and_hunks(data_obj: dict, CVE2CWE_OBJ, models, id):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE, CVE2CWE_OBJ)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks_temp = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                               buggy_code_obj['deletions']).extract_hunks()
        if len(hunks_temp) > 0:
            hunks[buggy_code_obj['file']] = hunks_temp

    description = data_obj['description']

    llm.set_models_pair(models)
    severity_llm_pack, cwe_llm_pack = llm.inference_with_description_and_hunks(description, hunks, gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE, CVE2CWE_OBJ)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE, CVE2CWE_OBJ)
    return formatter.format(id, severity_llm_pack, cwe_llm_pack, gt_CVE, gt_CWEs, gt_SEVERITIES,
                            gt_CVSS_versions,
                            data_obj['url'],
                            data_obj['description'], data_obj['date'], data_obj['github_description'])


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


def run_experiment(data_array, _list, runner, CVE2CWE_OBJ, models):
    data_array_length = len(data_array) if constants.MAX_NUMBER_OF_RECORDS_PER_EXPERIMENT == -1 else min(
        len(data_array),
        constants.MAX_NUMBER_OF_RECORDS_PER_EXPERIMENT)

    not_inferred_cases = list()
    counter = 0
    for idx, data_obj in enumerate(data_array):
        if counter >= constants.MAX_NUMBER_OF_FILTERED_RECORDS_PER_EXPERIMENT:
            print("Record url: ", data_obj['url'], "Records found: ",
                  100.0 * (counter) / constants.MAX_NUMBER_OF_FILTERED_RECORDS_PER_EXPERIMENT, "%", " | ",
                  "Dataset analysed: ", 100.0 * (idx + 1) / data_array_length)
            break
        print("Record url: ", data_obj['url'], "Records found: ", 100.0 * (counter) / constants.MAX_NUMBER_OF_FILTERED_RECORDS_PER_EXPERIMENT, "%", " | ", "Dataset analysed: ",100.0*(idx+1)/data_array_length)
        if utils.date_is_after(data_obj['date'], constants.LLM_MODEL_CUT_OFF_DATE):
            filtered_data_object = meets_buggy_code_details(data_obj, CVE2CWE_OBJ)
            if filtered_data_object[1] is None:
                if filtered_data_object[0] is None:
                    exit(0)
                counter += 1
                _list.append(runner(filtered_data_object[0], CVE2CWE_OBJ, models, idx + 1))
            else:
                not_inferred_cases.append(
                    {'id': idx + 1, 'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                     'reason': 'The record does not not meet the criteria. ' +
                               filtered_data_object[1]})
        else:
            not_inferred_cases.append(
                {'id': idx + 1, 'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                 'reason': 'The record is not new enough.'})
        if idx + 1 >= data_array_length:
            break

    return not_inferred_cases


if __name__ == '__main__':
    assert (constants.EXPERIMENT_STAGE and not constants.ANALYZE_STAGE) or (
            not constants.EXPERIMENT_STAGE and constants.ANALYZE_STAGE)

    evaluations_buggy_files = list()
    evaluations_buggy_methods = list()
    evaluations_buggy_hunks = list()
    evaluations_bug_description = list()
    evaluations_bug_description_and_files = list()
    evaluations_bug_description_and_methods = list()
    evaluations_bug_description_and_hunks = list()
    not_inferred_cases = list()

    # each tuple is for severity and CWE prediction models
    models_tuples = [(constants.LLM_NORMAL_MODEL, constants.LLM_NORMAL_MODEL),
                     (constants.LLM_SEVERITY_FINE_TUNED_MODEL, constants.LLM_CWE_FINE_TUNED_MODEL)]

    variants = [
        # ("final_analysis_of_buggy_files", evaluations_buggy_files, run_experiment_buggy_files),
        # ("final_analysis_of_buggy_methods", evaluations_buggy_methods, run_experiment_buggy_methods),
        # ("final_analysis_of_buggy_hunk", evaluations_buggy_hunks, run_experiment_buggy_hunks),

        ("final_analysis_of_bug_description", evaluations_bug_description, run_experiment_bug_description),
        ("final_analysis_of_bug_description_and_files", evaluations_bug_description_and_files,run_experiment_bug_description_and_files),
        ("final_analysis_of_bug_description_and_method", evaluations_bug_description_and_methods,run_experiment_bug_description_and_methods),
        ("final_analysis_of_bug_description_and_hunks", evaluations_bug_description_and_hunks,run_experiment_bug_description_and_hunks)
    ]

    if constants.EXPERIMENT_STAGE:
        print("STAGE ==> EXPERIMENT")
        data_array = utils.load_json_file(constants.EVALUATION_DATASET_PATH)
        CVE2CWE_OBJ = utils.load_json_file(constants.CVE2CWE_PATH)

        for models in models_tuples:
            print("\n======> Model: ", models)
            for idx, (exp_name, list_to_add, runner) in enumerate(variants):
                list_to_add = list()
                print(f"\n---> Experiment: {exp_name} | {idx + 1} of {len(variants)}")
                not_inferred_cases = run_experiment(data_array, list_to_add, runner, CVE2CWE_OBJ, models)
                utils.save_json(
                    f'{exp_name}_{utils.shorten_model_name(models[0])}_{utils.shorten_model_name(models[1])}.json',
                    list_to_add)

                print(
                    f"\nThe experiment result was successfully saved at {exp_name}.json file")
                if idx == len(variants) - 1:
                    utils.save_json('not_inferred_cases.json', not_inferred_cases)


    elif constants.ANALYZE_STAGE:
        print("STAGE ==> ANALYSIS")
        for models in models_tuples:
            for idx, (exp_name, _, _) in enumerate(variants):
                raw_experiment_result = utils.load_json_file(f'{exp_name}_{utils.shorten_model_name(models[0])}_{utils.shorten_model_name(models[1])}.json')
                evaluated_experiment_result = evaluator.analyze(raw_experiment_result)
                utils.save_json(f'evaluated_{exp_name}_{utils.shorten_model_name(models[0])}_{utils.shorten_model_name(models[1])}.json', evaluated_experiment_result)
                print(
                    f"\nThe experiment result was successfully saved at evaluated_{exp_name}.json file")
