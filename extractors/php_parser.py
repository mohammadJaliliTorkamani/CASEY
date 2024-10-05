import argparse
import json

import tree_sitter_php
from tree_sitter import Language, Parser


def main(file_path):
    code = open(file_path).read()
    parser = Parser()
    parser.language = Language(tree_sitter_php.language_php())
    tree = parser.parse(bytes(code, "utf8"))

    methods = extract_methods(tree.root_node, code.encode("utf8"))

    result = {"methods": methods}
    obj = json.dumps(result, indent=4)
    print(obj)


def extract_methods(node, code):
    methods = []
    if node.type == 'method_declaration' or node.type == 'function_definition':
        methods.append(node.text.decode('utf-8'))

    for child in node.children:
        methods.extend(extract_methods(child, code))

    return methods


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract methods from a PHP file.')
    parser.add_argument('file_path', type=str, help='Path to the PHP file')
    args = parser.parse_args()

    main(args.file_path)
