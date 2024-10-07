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


def run_experiment_buggy_files(data_obj: dict):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    llm_input, llm_output = llm.inference_with_buggy_files(data_obj['buggy_code'], gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def run_experiment_buggy_methods(data_obj: dict ):
    print(data_obj['url'])
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    methods = {}
    for buggy_code_obj in data_obj['buggy_code']:
        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                      buggy_code_obj['deletions']).extract_methods()
        if extracted_methods is not None:
            methods[buggy_code_obj['file']] = filter_methods(extracted_methods, buggy_code_obj['deletions'],
                                                             temp_file_path)

    llm_input, llm_output = llm.inference_with_buggy_methods(methods, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions, data_obj['url'],
                              data_obj['description'],data_obj['date'],data_obj['github_description'])


def run_experiment_buggy_hunks(data_obj: dict):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks[buggy_code_obj['file']] = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                  buggy_code_obj['deletions']).extract_hunks()

    llm_input, llm_output = llm.inference_with_buggy_hunks(hunks, gt_CVSS_versions)

    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def run_experiment_bug_description(data_obj):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    llm_input, llm_output = llm.inference_with_description(data_obj['description'], gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def run_experiment_bug_description_and_files(data_obj: dict):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    llm_input, llm_output = llm.inference_with_description_and_files(data_obj['description'], data_obj['buggy_code'],
                                                                     gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def extract_first_or_second_values(lst: list, extract_first: bool):
    return [x[0 if extract_first_or_second_values else 1] for x in lst]


def filter_methods(extracted_methods, deletions, temp_file_path: str):
    try:
        print("Deletions: ", deletions)
        filtered_methods = list()
        if deletions and len(deletions) > 0:
            for method in extracted_methods:
                method_range = utils.extract_line_range(method, temp_file_path)
                print("method range:", method_range)
                if method_range != (None, None):
                    for item in deletions:
                        if len(str(item['line_content']).strip()) > 0 and method_range[0] <= int(
                                item['line_number']) + 1 <= method_range[1]:
                            filtered_methods.append(method)

            print("Filtered methods length: ", len(filtered_methods))
            return filtered_methods

        return extracted_methods
    finally:
        utils.remove_file(temp_file_path)


# print(filter_methods(["def _to_text(obj, arg_encoding='utf-8', errors='strict', nonstring='strict'):\n    if isinstance(obj, str):\n        return obj\n    elif isinstance(obj, bytes):\n        return obj.decode(arg_encoding, errors)\n    else:\n        if nonstring == 'strict':\n            raise TypeError('First argument must be a string')\n        raise ValueError('nonstring must be one of: [\"strict\",]')", "def __init__(self, *args, alias_spec=None, **kwargs):\n        '''\n        Use the object dict.\n\n        Optional parameter 'alias_spec' is dictionary of form:\n        {'aliased_to': ['alias_one', 'alias_two', ...], ...}\n        When specified, and one of the aliases is accessed - the\n        'aliased_to' config option is returned.\n        '''\n        self.__dict__.update(*args, **kwargs)\n\n        self.sandbox = sandbox.SandboxedEnvironment(keep_trailing_newline=True)\n\n        self._aliases = {}\n        if alias_spec:\n            for aliased_to, aliases in alias_spec.items():\n                for alias in aliases:\n                    self._aliases[alias] = aliased_to", "def __setitem__(self, key, value):\n        key = self._aliases.get(key, key)\n        self.__dict__[key] = value", "def __getitem__(self, key):\n        key = self._aliases.get(key, key)\n        if '__jinja_expand' in self.__dict__ and self.__dict__['__jinja_expand']:\n            return self.__render_value(self.__dict__[key])\n        return self.__dict__[key]", "def __delitem__(self, key):\n        del self.__dict__[key]", "def __iter__(self):\n        return iter(self.__dict__)", "def __len__(self):\n        return len(self.__dict__)", "def __str__(self):\n        '''returns simple dict representation of the mapping'''\n        return str(self.__dict__)", "def __repr__(self):\n        '''echoes class, id, & reproducible representation in the REPL'''\n        return '{}, TemplatedDictionary({})'.format(super(TemplatedDictionary, self).__repr__(),\n                                                    self.__dict__)", "def copy(self):\n        return TemplatedDictionary(self.__dict__)", "def __render_value(self, value):\n        if isinstance(value, str):\n            return self.__render_string(value)\n        elif isinstance(value, list):\n            # we cannot use list comprehension here, as we need to NOT modify the list (pointer to list)\n            # and we need to modifiy only individual values in the list\n            # If we would create new list, we cannot assign to it, which often happens in configs (e.g. plugins)\n            for i in range(len(value)):  # pylint: disable=consider-using-enumerate\n                value[i] = self.__render_value(value[i])\n            return value\n        elif isinstance(value, dict):\n            # we cannot use list comprehension here, same reasoning as for `list` above\n            for k in value.keys():\n                value[k] = self.__render_value(value[k])\n            return value\n        else:\n            return value", "def __render_string(self, value):\n        orig = last = value\n        max_recursion = self.__dict__.get('jinja_max_recursion', 5)\n        for _ in range(max_recursion):\n            value = _to_native(self.sandbox.from_string(value).render(self.__dict__, func=lambda:None))\n            if value == last:\n                return value\n            last = value\n        raise ValueError(\"too deep jinja re-evaluation on '{}'\".format(orig))"],
#     [{'line_number': 84, 'line_content': 'value = _to_native(self.sandbox.from_string(value).render(self.__dict__, func=lambda:None))'}],'temp.py'))
# exit(0)
def run_experiment_bug_description_and_methods(data_obj: dict):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    methods = {}
    for buggy_code_obj in data_obj['buggy_code']:
        extracted_methods, temp_file_path = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                      buggy_code_obj['deletions']).extract_methods()
        if extracted_methods is not None:
            methods[buggy_code_obj['file']] = filter_methods(extracted_methods, buggy_code_obj['deletions'],
                                                             temp_file_path)

    llm_input, llm_output = None, None
    if len(methods) > 0:
        llm_input, llm_output = llm.inference_with_description_and_methods(data_obj['description'], methods,
                                                                           gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def run_experiment_bug_description_and_hunks(data_obj: dict):
    gt_CVE = data_obj['CVE']
    gt_CVSS_versions = utils.extract_cvss_versions(gt_CVE)
    hunks = {}
    for buggy_code_obj in data_obj['buggy_code']:
        hunks[buggy_code_obj['file']] = Extractor(buggy_code_obj['file'], buggy_code_obj['file_content'],
                                                  buggy_code_obj['deletions']).extract_hunks()

    llm_input, llm_output = llm.inference_with_description_and_hunks(data_obj['description'], hunks, gt_CVSS_versions)
    gt_CWEs = list(set(utils.get_CWEs_of_CVE(gt_CVE)))
    gt_SEVERITIES = utils.get_severities_of_CVE(gt_CVE)
    return evaluator.evaluate(llm_input, llm_output, gt_CVE, gt_CWEs, gt_SEVERITIES, gt_CVSS_versions)


def meets_buggy_code_details(data_obj) -> tuple:
    total_number_of_tokens = 0
    new_buggy_codes = []
    for item in data_obj['buggy_code']:
        if 'file' in item and item['file'].split('.')[-1] in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS:
            total_number_of_tokens += utils.count_gpt_tokens(item['file_content'])
            if total_number_of_tokens < constants.MAX_TOKEN_NUMBER:
                new_buggy_codes.append(item)
            else:
                return None, f"TOKEN_EXCEEDED ({total_number_of_tokens})"

    if len(new_buggy_codes) > 0:
        data_obj['buggy_code'] = new_buggy_codes
        return data_obj, None
    return None, "NON-ACCEPTABLE_FILE_TYPE"


if __name__ == '__main__':
    data_array = utils.load_json_file(constants.SMALL_DATA_PATH)
    random.shuffle(data_array)
    evaluations_buggy_files = list()
    evaluations_buggy_methods = list()
    evaluations_buggy_hunks = list()
    evaluations_bug_description = list()
    evaluations_bug_description_and_files = list()
    evaluations_bug_description_and_methods = list()
    evaluations_bug_description_and_hunks = list()
    not_inferred_cases = list()
    for idx, data_obj in enumerate(data_array):
        print("################################")
        print("Record: ", data_obj['url'])
        if utils.date_is_after(data_obj['date'], constants.LLM_MODEL_CUT_OFF_DATE):
            filtered_data_object = meets_buggy_code_details(data_obj)
            if filtered_data_object[1] is None:
                assert filtered_data_object[0] is not None
                # evaluations_buggy_files.append(run_experiment_buggy_files(filtered_data_object[0],data_obj))
                evaluations_buggy_methods.append(run_experiment_buggy_methods(filtered_data_object[0]))
                # evaluations_buggy_hunks.append(run_experiment_buggy_hunks(filtered_data_object[0],data_obj))
                # evaluations_bug_description.append(run_experiment_bug_description(filtered_data_object[0],data_obj))
                # evaluations_bug_description_and_files.append(
                #     run_experiment_bug_description_and_files(filtered_data_object[0],data_obj))
                # evaluations_bug_description_and_methods.append(
                #     run_experiment_bug_description_and_methods(filtered_data_object[0],data_obj))
                # evaluations_bug_description_and_hunks.append(
                #     run_experiment_bug_description_and_hunks(filtered_data_object[0],data_obj))
            else:
                not_inferred_cases.append({'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                                           'reason': 'The record does not not meet the criteria. ' +
                                                     filtered_data_object[1]})
                print("The record does not not meet the criteria.")
        else:
            not_inferred_cases.append({'url': data_obj['url'], 'CVE': data_obj['CVE'], 'date': data_obj['date'],
                                       'reason': 'The record is not new enough.'})
            print("The record is not new enough.")

        print(str(idx + 1) + " of " + str(len(data_array)) + " record(s) have been processed")

    save_to_json('not_inferred_cases.json', not_inferred_cases)

    # final_analysis1 = Evaluator.analyze_evaluations(evaluations_buggy_files)
    final_analysis2 = Evaluator.analyze_evaluations(evaluations_buggy_methods)
    # final_analysis3 = Evaluator.analyze_evaluations(evaluations_buggy_hunks)
    # final_analysis4 = Evaluator.analyze_evaluations(evaluations_bug_description)
    # final_analysis5 = Evaluator.analyze_evaluations(evaluations_bug_description_and_files)
    # final_analysis6 = Evaluator.analyze_evaluations(evaluations_bug_description_and_methods)
    # final_analysis7 = Evaluator.analyze_evaluations(evaluations_bug_description_and_hunks)
    # save_to_json('final_analysis_of_buggy_files.json', final_analysis1)
    save_to_json('final_analysis_of_buggy_methods.json', final_analysis2)
    # save_to_json('final_analysis_of_buggy_hunks.json', final_analysis3)
    # save_to_json('final_analysis_of_bug_description.json', final_analysis4)
    # save_to_json('final_analysis_of_bug_description_and_files.json', final_analysis5)
    # save_to_json('final_analysis_of_bug_description_and_methods.json', final_analysis6)
    # save_to_json('final_analysis_of_bug_description_and_hunks.json', final_analysis7)
