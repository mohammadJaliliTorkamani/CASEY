import json
import os
import subprocess

import constants
import utils


def extract_java_methods(file_name) -> list:
    command = f'java -jar "{constants.JAVA_EXTRACTOR_JAR_FILE_PATH}" "{file_name}"'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return json.loads(stdout.decode('utf-8'))['methods']


def execute_methods_extractor_python_script(script_name: str, file_name: str):
    # Define the command to activate the virtual environment and run the Python script
    activate_script = os.path.join('.venv', 'bin', 'activate')
    command = f'source {activate_script} && python "{script_name}" "{file_name}"'

    print("Command:", command)

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error executing script: {stderr} | {stdout}")
        return None

    print("STDOUT:", stdout.decode('utf-8'))

    return json.loads(stdout.decode('utf-8'))['methods']


def extract_python_methods(file_name):
    return execute_methods_extractor_python_script(constants.PYTHON_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_js_methods(file_name):
    return execute_methods_extractor_python_script(constants.JS_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_php_methods(file_name):
    return execute_methods_extractor_python_script(constants.PHP_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_ts_methods(file_name):
    return execute_methods_extractor_python_script(constants.TS_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_c_methods(file_name):
    return execute_methods_extractor_python_script(constants.C_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_go_methods(file_name):
    return execute_methods_extractor_python_script(constants.GO_EXTRACTOR_SCRIPT_PATH, file_name)


def extract_ruby_methods(file_name):
    return execute_methods_extractor_python_script(constants.RB_EXTRACTOR_SCRIPT_PATH, file_name)


class Extractor:
    def __init__(self, file_relative_path, file_content, raw_hunks):
        self.file_content = file_content
        self.relative_path = file_relative_path
        self.hunks = raw_hunks

    # TODO (do not forget to extract based on the file type) <Follow the sample output value>
    def extract_methods(self):
        file_extension = str(self.relative_path.split('/')[-1].split('.')[-1]).lower()
        file_name = constants.TEMP_CONTENT_FILE_NAME_FOR_METHOD_EXTRACTOR + "." + file_extension
        utils.save_file(file_name, self.file_content)
        if file_extension == 'php':
            return extract_php_methods(file_name), file_name
        elif file_extension == 'js':
            return extract_js_methods(file_name), file_name
        elif file_extension == 'go':
            return extract_go_methods(file_name), file_name
        elif file_extension == 'ts':
            return extract_ts_methods(file_name), file_name
        elif file_extension == 'py':
            return extract_python_methods(file_name), file_name
        elif file_extension == 'c':
            return extract_c_methods(file_name), file_name
        elif file_extension == 'rb':
            return extract_ruby_methods(file_name), file_name
        elif file_extension == 'java':
            return extract_java_methods(file_name), file_name

    def extract_hunks(self) -> list:
        _hunk_lines = list()
        for hunk in self.hunks:
            _hunk_lines.append(hunk['line_content'])
        return _hunk_lines
