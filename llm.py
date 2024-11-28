import json
import time

from openai import OpenAI
from openai.types.chat import ChatCompletion

import constants
import utils
from utils import print_nested


class LLM:
    def __init__(self, models: tuple[str,str]):
        self.__models = models
        self.client = OpenAI(api_key=constants.OPENAI_API_KEY)

    def set_models_pair(self, models: tuple[str, str]):
        assert {models[0], models[1]}.issubset([constants.LLM_NORMAL_MODEL, constants.LLM_CWE_FINE_TUNED_MODEL,
                                                constants.LLM_SEVERITY_FINE_TUNED_MODEL])
        self.__models = models

    def extract_message(self, response: ChatCompletion) -> str | None:
        try:
            return response.choices[0].message.content
        except Exception:
            return None

    def __inference(self, user_input: str, system_field: str, model: str, tag: str = None) -> (str, str | None):
        system_field = system_field.strip()
        user_input = user_input.strip()
        input_message = [{'role': 'system', 'content': system_field}]
        input_message.append(
            {'role': 'user',
             'content': user_input})

        trial_number = constants.OPENAI_LLM_MAX_TRIAL
        if utils.count_gpt_tokens(user_input) + utils.count_gpt_tokens(system_field) >= constants.MAX_TOKEN_NUMBER:
            return input_message, None

        while trial_number > 0:
            response = None
            try:
                response = self.client.chat.completions.create(model=model,
                                                               temperature=constants.LLM_TEMPERATURE,
                                                               top_p=constants.LLM_TOP_P, stream=False,
                                                               presence_penalty=constants.LLM_PRESENCE_PENALTY,
                                                               frequency_penalty=constants.LLM_FREQUENCY_PENALTY,
                                                               messages=input_message
                                                               )

                output_message = utils.extract_json_from_string(self.extract_message(response))
                output_message = utils.fix_json_string(output_message)
                if (output_message is not None and
                        utils.is_not_in_list(constants.LLM_RESPONSE_ERROR_SIGNS, output_message) and
                        json.loads(output_message) is not None):
                    return input_message, output_message
                else:
                    trial_number -= 1
            except Exception as e:
                print_nested("Error <Tag: " + ("Empty" if tag is None else tag)+">")
                print_nested(str(e))
                trial_number -= 1

            print_nested(
                f"invalid LLM response (Tag: {'Empty' if tag is None else tag}). Trying again after {constants.LLM_TRIAL_GAP_SECONDS} "
                f"seconds... | received response: {response} | User: {user_input}", 1)
            time.sleep(constants.LLM_TRIAL_GAP_SECONDS)

        return input_message, None

    def inference_with_description(self, description: str, cvss_versions: list, return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]

        user_input = "Description: " + description

        if return_input_fields:
            if description is None or len(description) == 0:
                return None, None, None, None

            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_SEVERITY % (
                cvss_version,
                cvss_version,
                CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_CWE

        i_severity, o_severity = self.__inference(user_input,
                                                  constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_SEVERITY % (
                                                      cvss_version,
                                                      cvss_version,
                                                      CVSS_severity_description), self.__models[0])
        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_CWE,
                                        self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_buggy_files(self, buggy_code, cvss_versions: list, return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        user_input = ""
        for item in buggy_code:
            user_input += f"File: {item['file']}\nContent: \n{constants.CODE_TAGS[0]}\n{item['file_content']}\n{constants.CODE_TAGS[1]}\n\n"

        if return_input_fields:
            if buggy_code is None or len(buggy_code) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_SEVERITY % (cvss_version, cvss_version,
                                                                                     CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_CWE

        i_severity, o_severity = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_SEVERITY % (
            cvss_version, cvss_version, CVSS_severity_description), self.__models[0])
        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_FILE_CWE, self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_buggy_methods(self, methods: dict, cvss_versions: list, return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        i, o = None, None
        user_input = ""
        for (file_name, _methods) in methods.items():
            if len(_methods) > 0:
                user_input += ('File: ' + file_name + '\nMethods:\n')
                for method in _methods:
                    user_input += (constants.METHOD_TAGS[0] + "\n" + method + "\n" + constants.METHOD_TAGS[1] + "\n")

        if return_input_fields:
            if methods is None or len(methods) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_SEVERITY % (
                cvss_version, cvss_version,
                CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_CWE

        i_severity, o_severity = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_SEVERITY % (
            cvss_version, cvss_version, CVSS_severity_description), self.__models[0])

        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_METHOD_CWE, self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_buggy_hunks(self, hunks: dict, cvss_versions: list, return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        i, o = None, None
        user_input = ""
        for (file_name, hunk_lines) in hunks.items():
            user_input = ('File: ' + file_name + '\nHunks:\n')
            for hunk in hunk_lines:
                user_input += (constants.HUNK_TAGS[0] + "\n" + hunk + "\n" + constants.HUNK_TAGS[1] + "\n")

        if return_input_fields:
            if hunks is None or len(hunks) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_SEVERITY % (cvss_version, cvss_version,
                                                                                      CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_CWE

        i_severity, o_severity = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_SEVERITY % (
            cvss_version, cvss_version, CVSS_severity_description), self.__models[0])

        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUGGY_HUNKS_CWE, self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_description_and_files(self, description, buggy_code, cvss_versions: list,
                                             return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        user_input = "Description: " + description + "\n"
        for item in buggy_code:
            if item['file'].split('.')[-1] in constants.ACCEPTABLE_EXPERIMENT_FILE_EXTENSIONS:
                user_input += f"File: {item['file']}\nContent: \n{constants.CODE_TAGS[0]}\n{item['file_content']}\n{constants.CODE_TAGS[1]}\n\n"

        if return_input_fields:
            if description is None or len(description) == 0 or buggy_code is None or len(buggy_code) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_SEVERITY % (
                cvss_version, cvss_version,
                CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_CWE

        i_severity, o_severity = self.__inference(user_input,
                                                  constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_SEVERITY % (
                                                      cvss_version, cvss_version, CVSS_severity_description),
                                                  self.__models[0])

        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_FILES_CWE,
                                        self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_description_and_methods(self, description, methods_list: dict, cvss_versions: list,
                                               return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        i, o = None, None
        user_input = "Description: " + description + "\n"
        for (file_name, methods) in methods_list.items():
            if len(methods) > 0:
                user_input += ('File: ' + file_name + '\nMethods:\n')
                for method in methods:
                    user_input += (constants.METHOD_TAGS[0] + "\n" + method + "\n" + constants.METHOD_TAGS[1] + "\n")

        if return_input_fields:
            if description is None or len(description) == 0 or methods_list is None or len(methods_list) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_SEVERITY % (
                cvss_version, cvss_version,
                CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_CWE
        i_severity, o_severity = self.__inference(user_input,
                                                  constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_SEVERITY % (
                                                      cvss_version, cvss_version, CVSS_severity_description),
                                                  self.__models[0])

        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_METHODS_CWE,
                                        self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)

    def inference_with_description_and_hunks(self, description, hunks: dict, cvss_versions: list,
                                             return_input_fields: bool = False):
        cvss_version = cvss_versions[0] if len(cvss_versions) > 0 else constants.DEFAULT_SEVERITY_VERSION_FOR_CVSS
        CVSS_severity_description = constants.CVSS_SEVERITY_DESCRIPTIONS[cvss_version]
        i, o = None, None
        user_input = "Description: " + description + "\n"
        for (file_name, hunk_lines) in hunks.items():
            user_input += ('File: ' + file_name + '\nHunks:\n')
            for hunk in hunk_lines:
                user_input += (constants.HUNK_TAGS[0] + "\n" + hunk + "\n" + constants.HUNK_TAGS[1] + "\n")

        if return_input_fields:
            if description is None or len(description) == 0 or hunks is None or len(hunks) == 0:
                return None, None, None, None
            return user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_SEVERITY % (
                cvss_version, cvss_version,
                CVSS_severity_description), user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_CWE

        i_severity, o_severity = self.__inference(user_input,
                                                  constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_SEVERITY % (
                                                      cvss_version, cvss_version, CVSS_severity_description),
                                                  self.__models[0])

        i_cwe, o_cwe = self.__inference(user_input, constants.LLM_SYSTEM_FIELD_FOR_BUG_DESCRIPTION_AND_HUNKS_CWE,
                                        self.__models[1])

        return ('SEVERITY', i_severity, o_severity), ('CWE', i_cwe, o_cwe)
