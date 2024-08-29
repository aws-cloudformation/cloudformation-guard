"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validate = void 0;
const guard_1 = require("./guard");
const path = require("node:path");
const fs = require("fs");
const DATA_FILE_SUPPORTED_EXTENSIONS = ['.yaml', '.yml', '.json', '.jsn', '.template'];
const RULE_FILE_SUPPORTED_EXTENSIONS = ['.guard', '.ruleset'];
const formatOutput = ({ result, rulesNames, dataNames }) => {
    const dataPattern = /DATA_STDIN\[(\d+)\]/g;
    const rulesPattern = /RULES_STDIN\[(\d+)\]\/DEFAULT/g;
    const isWindows = process.platform === 'win32';
    const output = JSON.parse(JSON.stringify(result).replace(dataPattern, (match, index) => {
        const fileIndex = parseInt(index, 10) - 1;
        const fileName = dataNames[fileIndex];
        return fileName ? (isWindows ? fileName.split('\\').join('/') : fileName) : match;
    }).replace(rulesPattern, (match, index) => {
        const ruleIndex = parseInt(index, 10) - 1;
        const ruleName = rulesNames[ruleIndex];
        if (ruleName) {
            const fileNameWithoutExtension = path.basename(ruleName, path.extname(ruleName));
            return fileNameWithoutExtension.toUpperCase();
        }
        return match;
    }));
    return JSON.parse(output);
};
async function readFiles(pathOrFile, supportedExtensions) {
    const fileNames = [];
    const fileContents = [];
    const stat = await fs.promises.stat(pathOrFile);
    if (stat.isDirectory()) {
        const files = await getAllFiles(pathOrFile, supportedExtensions);
        const readPromises = files.map(async (file) => {
            const content = await fs.promises.readFile(file, 'utf8');
            fileNames.push(file);
            fileContents.push(content);
        });
        await Promise.all(readPromises);
    }
    else if (stat.isFile() && supportedExtensions.includes(path.extname(pathOrFile))) {
        const content = await fs.promises.readFile(pathOrFile, 'utf8');
        fileNames.push(pathOrFile);
        fileContents.push(content);
    }
    return {
        fileContents,
        fileNames,
    };
}
async function getAllFiles(dirPath, supportedExtensions) {
    const files = [];
    const dirEntries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    const traversalPromises = dirEntries.map(async (entry) => {
        const entryPath = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
            const subFiles = await getAllFiles(entryPath, supportedExtensions);
            files.push(...subFiles);
        }
        else if (supportedExtensions.includes(path.extname(entryPath))) {
            files.push(entryPath);
        }
    });
    await Promise.all(traversalPromises);
    return files;
}
const validate = async ({ rulesPath, dataPath }) => {
    const rulesResult = await readFiles(rulesPath, RULE_FILE_SUPPORTED_EXTENSIONS);
    const dataResult = await readFiles(dataPath, DATA_FILE_SUPPORTED_EXTENSIONS);
    const payload = {
        rules: rulesResult.fileContents,
        data: dataResult.fileContents,
    };
    const validateBuilder = new guard_1.ValidateBuilder();
    const result = validateBuilder
        .payload(true)
        .structured(true)
        .showSummary([guard_1.ShowSummaryType.None])
        .outputFormat(guard_1.OutputFormatType.Sarif)
        .tryBuildAndExecute(JSON.stringify(payload));
    return formatOutput({
        result,
        rulesNames: rulesResult.fileNames,
        dataNames: dataResult.fileNames,
    });
};
exports.validate = validate;
