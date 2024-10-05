import json
import time

from openai import OpenAI
from openai.types.chat import ChatCompletion

import constants
import utils
from utils import print_nested


class LLM:
    def __init__(self, model: str):
        self.model = model
        self.client = OpenAI(api_key=constants.OPENAI_API_KEY)

    def extract_message(self, response: ChatCompletion) -> str | None:
        try:
            return response.choices[0].message.content
        except Exception:
            return None

    def __inference(self, user_input: str, system_field: str) -> (str, str | None):
        input_message = [{'role': 'system', 'content': system_field}]
        input_message.append(
            {'role': 'user',
             'content': user_input})

        trial_number = constants.OPENAI_LLM_MAX_TRIAL
        while trial_number > 0:
            try:
                response = self.client.chat.completions.create(model=self.model, temperature=constants.LLM_TEMPERATURE,
                                                               top_p=constants.LLM_TOP_P, stream=False,
                                                               presence_penalty=constants.LLM_PRESENCE_PENALTY,
                                                               frequency_penalty=constants.LLM_FREQUENCY_PENALTY,
                                                               messages=input_message
                                                               )

                output_message = utils.extract_json_from_string(self.extract_message(response))
                if (output_message is not None and
                        utils.is_not_in_list(constants.LLM_RESPONSE_ERROR_SIGNS, output_message) and
                        json.loads(output_message) is not None):
                    return input_message, output_message
                else:
                    trial_number -= 1
            except Exception as e:
                print_nested(str(e))
                trial_number -= 1

            print_nested(f"invalid LLM response. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} "
                         f"seconds...", 1)
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)

        return input_message, None

    def inference_with_description(self, description: str, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            user_input = "Description: " + description

            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))

            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f"Failed to infer a non-empty CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)
            counter -= 1
        return i, o

    def inference_with_buggy_files(self, buggy_code, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        user_input = ""
        for item in buggy_code:
            if item['file'].split('.')[-1] in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS:
                user_input += f"File: {item['file']}\nContent: \n{constants.CODE_TAGS[0]}\n{item['file_content']}\n{constants.CODE_TAGS[1]}\n\n"

        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_FILE % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f"Failed to infer a non-empty CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            counter -= 1
        return i, o

    def inference_with_buggy_methods(self, methods: dict, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            user_input = ""
            for (file_name, _methods) in methods.items():
                user_input = ('File: ' + file_name + '\nMethods:\n')
                for method in _methods:
                    user_input += (constants.METHOD_TAGS[0] + "\n" + method + constants.METHOD_TAGS[1] + "\n")

            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if o is not None and len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f" CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)
            counter -= 1
        return i, o

    def inference_with_buggy_hunks(self, hunks: dict, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            user_input = ""
            for (file_name, hunk_lines) in hunks.items():
                user_input = ('File: ' + file_name + '\nHunks:\n')
                for hunk in hunk_lines:
                    user_input += (constants.HUNK_TAGS[0] + "\n" + hunk + constants.HUNK_TAGS[1] + "\n")

            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f" CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)
            counter -= 1
        return i, o

    def inference_with_description_and_files(self, description, buggy_code, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        user_input = "Description: " + description + "\n"
        for item in buggy_code:
            if item['file'].split('.')[-1] in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS:
                user_input += f"File: {item['file']}\nContent: \n{constants.CODE_TAGS[0]}\n{item['file_content']}\n{constants.CODE_TAGS[1]}\n\n"

        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f"Failed to infer a non-empty CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            counter -= 1
        return i, o

    def inference_with_description_and_methods(self, description, methods_list: dict, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            user_input = "Description: " + description + "\n"
            for (file_name, methods) in methods_list.items():
                user_input += ('File: ' + file_name + '\nMethods:\n')
                for method in methods:
                    user_input += (constants.METHOD_TAGS[0] + "\n" + method + constants.METHOD_TAGS[1] + "\n")

            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f"Failed to infer a non-empty CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)
            counter -= 1
        return i, o

    def inference_with_description_and_hunks(self, description, hunks: dict, cvss_versions: list):
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[
            cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS]
        counter = constants.EMPTY_CWEs_MAX_TRIAL
        i, o = None, None
        while counter > 0:
            user_input = "Description: " + description + "\n"
            for (file_name, hunk_lines) in hunks.items():
                user_input += ('File: ' + file_name + '\nHunks:\n')
                for hunk in hunk_lines:
                    user_input += (constants.HUNK_TAGS[0] + "\n" + hunk + constants.HUNK_TAGS[1] + "\n")

            i, o = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS % (
                (cvss_versions[0] if len(cvss_versions) > 0 else ""), CVSS_severity_description))
            if len(json.loads(o)['CWE_IDS']) > 0:
                return i, o
            print(
                f"Failed to infer a non-empty CWE_IDs. Trying again after {constants.LLM_TRIAL_GAP_SECONDS} seconds...")
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)
            counter -= 1
        return i, o
