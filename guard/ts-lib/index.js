"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate = void 0;
const guard_1 = require("./guard");
const validateBuilder = new guard_1.ValidateBuilder();
const path = require('node:path');
const fs = require("fs");
const DATA_FILE_SUPPORTED_EXTENSIONS = [".yaml", ".yml", ".json", ".jsn", ".template"];
const RULE_FILE_SUPPORTED_EXTENSIONS = [".guard", ".ruleset"];
const formatOutput = ({ inputString, rulesNames, dataNames }) => {
    const dataPattern = /DATA_STDIN\[(\d+)\]/g;
    const rulesPattern = /RULES_STDIN\[(\d+)\]\/DEFAULT/g;
    const output = inputString.replace(dataPattern, (match, index) => {
        const fileIndex = parseInt(index, 10) - 1;
        const fileName = dataNames[fileIndex];
        return fileName ? fileName.replace(/^\//, '') : match;
    }).replace(rulesPattern, (match, index) => {
        const ruleIndex = parseInt(index, 10) - 1;
        const ruleName = rulesNames[ruleIndex];
        if (ruleName) {
            const fileNameWithoutExtension = path.basename(ruleName, path.extname(ruleName));
            return fileNameWithoutExtension.toUpperCase();
        }
        return match;
    });
    return JSON.parse(JSON.parse(output));
};
async function readFilesRecursively(parentDir) {
    const fileNames = [];
    const fileContents = [];
    async function traverseDirectory(currentDir) {
        try {
            const files = await fs.promises.readdir(currentDir, { withFileTypes: true });
            const readPromises = files.map(async (file) => {
                const filePath = path.join(currentDir, file.name);
                if (file.isDirectory()) {
                    await traverseDirectory(filePath);
                }
                else {
                    if ([...DATA_FILE_SUPPORTED_EXTENSIONS, ...RULE_FILE_SUPPORTED_EXTENSIONS].includes(path.extname(filePath))) {
                        const content = await fs.promises.readFile(filePath, 'utf8');
                        fileNames.push(filePath);
                        fileContents.push(content);
                    }
                }
            });
            await Promise.all(readPromises);
        }
        catch (err) {
            console.error('Error reading files:', err);
        }
    }
    await traverseDirectory(parentDir);
    return {
        fileContents,
        fileNames
    };
}
const validate = async ({ rulesPath, dataPath, }) => {
    const rulesResult = await readFilesRecursively(rulesPath);
    const dataResult = await readFilesRecursively(dataPath);
    const payload = {
        rules: rulesResult.fileContents,
        data: dataResult.fileContents
    };
    const validateBuilder = new guard_1.ValidateBuilder();
    const result = validateBuilder
        .payload(true)
        .structured(true)
        .show_summary([guard_1.ShowSummaryType.None])
        .output_format(guard_1.OutputFormatType.Sarif)
        .try_build_js(JSON.stringify(payload));
    const formattedOutput = formatOutput({
        inputString: JSON.stringify(result),
        rulesNames: rulesResult.fileNames,
        dataNames: dataResult.fileNames
    });
    debugger;
    return formattedOutput;
};
exports.validate = validate;
