const esprima = require('esprima');
const fs = require('fs');

function parseJSFile(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = esprima.parseScript(content, {range: true});

    let methods = [];

    function traverse(node, parentType = null) {
        if (
            (node.type === 'FunctionDeclaration' ||
                node.type === 'FunctionExpression' ||
                (node.type === 'MethodDefinition' && node.key && node.key.name) ||
                (node.type === 'Property' && node.value && (node.value.type === 'FunctionExpression' || node.value.type === 'ArrowFunctionExpression'))) &&
            node.body &&
            node.body.range
        ) {
            let start = node.range[0];
            let end = node.range[1];
            let fullFunction = content.slice(start, end);

            // If it's a function expression and doesn't have a name, we keep it as is
            if (node.type === 'FunctionExpression' && !node.id) {
                methods.push(fullFunction);
            } else if (node.type === 'Property' || node.type === 'MethodDefinition') {
                let name = node.key.name;
                methods.push(fullFunction);
            } else {
                methods.push(fullFunction);
            }
        } else if (node.type !== 'ArrowFunctionExpression') {
            for (let key in node) {
                if (node[key] && typeof node[key] === 'object') {
                    traverse(node[key], node.type);
                }
            }
        }
    }

    traverse(parsed);

    return methods;
}

const filePath = process.argv[2];
if (!filePath) {
    console.error('Usage: node parse_js.js <path_to_js_file>');
    process.exit(1);
}

const methods = parseJSFile(filePath);
console.log(JSON.stringify(methods, null, 4));
