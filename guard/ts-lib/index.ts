import { OutputFormatType, ShowSummaryType, ValidateBuilder } from "./guard";
const path = require('node:path');
import * as fs from 'fs';

const DATA_FILE_SUPPORTED_EXTENSIONS =
    [".yaml", ".yml", ".json", ".jsn", ".template"];
const RULE_FILE_SUPPORTED_EXTENSIONS = [".guard", ".ruleset"];

interface TraversalResult {
  fileNames: string[];
  fileContents: string[];
}

interface formatOutputParams {
  inputString: string;
  rulesNames: string[];
  dataNames: string[];
}

export interface SarifReport {
  $schema: string;
  runs: SarifRun[];
  version: string;
}

export interface SarifRun {
  artifacts: SarifArtifact[];
  results: SarifResult[];
  tool: SarifTool;
}

export interface SarifArtifact {
  location: SarifLocation;
}

export interface SarifLocation {
  uri: string;
}

export interface SarifResult {
  level: string;
  locations: SarifPhysicalLocation[];
  message: SarifMessage;
  ruleId: string;
}

export interface SarifPhysicalLocation {
  physicalLocation: {
    artifactLocation: SarifArtifactLocation;
    region: SarifRegion;
  };
}

export interface SarifArtifactLocation {
  uri: string;
}

export interface SarifRegion {
  startColumn: number;
  startLine: number;
}

export interface SarifMessage {
  text: string;
}

export interface SarifTool {
  driver: SarifDriver;
}

export interface SarifDriver {
  downloadUri: string;
  fullName: string;
  informationUri: string;
  name: string;
  organization: string;
  semanticVersion: string;
  shortDescription: SarifShortDescription;
}

export interface SarifShortDescription {
  text: string;
}

const formatOutput = ({ inputString, rulesNames, dataNames }: formatOutputParams): SarifReport => {
  const dataPattern = /DATA_STDIN\[(\d+)\]/g;
  const rulesPattern = /RULES_STDIN\[(\d+)\]\/DEFAULT/g;

  const output = inputString.replace(dataPattern, (match: string, index: string) => {
    const fileIndex = parseInt(index, 10) - 1;
    const fileName = dataNames[fileIndex];
    return fileName ? fileName.replace(/^\//, '') : match;
  }).replace(rulesPattern, (match: string, index: string) => {
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

async function readFilesRecursively(parentDir: string): Promise<TraversalResult> {
  const fileNames: string[] = [];
  const fileContents: string[] = [];

  async function traverseDirectory(currentDir: string): Promise<void> {
    try {
      const files = await fs.promises.readdir(currentDir, { withFileTypes: true });
      const readPromises = files.map(async (file) => {
        const filePath = path.join(currentDir, file.name);
        if (file.isDirectory()) {
          await traverseDirectory(filePath);
        } else {
          if ([...DATA_FILE_SUPPORTED_EXTENSIONS, ...RULE_FILE_SUPPORTED_EXTENSIONS].includes(path.extname(filePath))) {
            const content = await fs.promises.readFile(filePath, 'utf8');
            fileNames.push(filePath);
            fileContents.push(content);
          }
        }
      });
      await Promise.all(readPromises);
    } catch (err) {
      console.error('Error reading files:', err);
    }
  }

  await traverseDirectory(parentDir);
  return {
    fileContents,
    fileNames
  };
}

interface ValidateParams {
  rulesPath: string;
  dataPath: string;
}

export const validate = async({
  rulesPath,
  dataPath,
}: ValidateParams): Promise<SarifReport> => {
  const rulesResult = await readFilesRecursively(rulesPath)
  const dataResult = await readFilesRecursively(dataPath)

  const payload = {
    rules: rulesResult.fileContents,
    data: dataResult.fileContents
  }

  const validateBuilder = new ValidateBuilder();

  const result: SarifReport = validateBuilder
    .payload(true)
    .structured(true)
    .showSummary([ShowSummaryType.None])
    .outputFormat(OutputFormatType.Sarif)
    .tryBuildAndExecute(JSON.stringify(payload))

  const formattedOutput: SarifReport = formatOutput({
    inputString: JSON.stringify(result),
    rulesNames: rulesResult.fileNames,
    dataNames: dataResult.fileNames
  })

  return formattedOutput
}
