import json
import os
import subprocess
import sys

def install_esprima():
    try:
        # Install esprima using npm
        subprocess.check_call(['npm', 'install', 'esprima'])
        print("esprima installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install esprima: {e}")
        sys.exit(1)

def extract_methods(js_file_path):
    install_esprima()
    result = subprocess.run(['node', '/Users/joeyng/PycharmProjects/BugType_Categorization/extractors/parse_js.js', js_file_path], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return json.loads(result.stdout)


def main():
    if len(sys.argv) != 2:
        print("Usage: python extract_js_methods.py <path_to_js_file>")
        sys.exit(1)

    js_file_path = sys.argv[1]
    if not os.path.isfile(js_file_path):
        print(f"File not found: {js_file_path}")
        sys.exit(1)

    methods = extract_methods(js_file_path)

    # Create a dictionary with methods under the "methods" field
    methods_json = {
        "methods": methods
    }

    # Print the JSON object
    print(json.dumps(methods_json, indent=4))


if __name__ == "__main__":
    main()
